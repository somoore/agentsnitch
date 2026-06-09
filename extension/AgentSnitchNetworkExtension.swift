/*
 * AgentSnitchNetworkExtension.swift
 *
 * Minimal skeleton for a macOS Network Extension (System Extension) provider.
 * Implements NEFilterDataProvider for observation + attribution (PID via audit token,
 * signing info, remote endpoint, and best-effort destination host hints).
 *
 * This is research scaffolding. It logs to unified logging and sends FlowEvent
 * JSON over the shared AgentSnitchXPCProtocol when the host listener is present.
 *
 * To use:
 * - Compile as the principal class of a macOS System Extension target (NSExtensionPointIdentifier
 *   com.apple.networkextension.filter-data).
 * - Bundle the resulting executable + Info.plist as <bundle-id>.systemextension inside the
 *   host app's Contents/Library/SystemExtensions/.
 * - Host app must request activation via OSSystemExtensionRequest.
 *
 * See extension/integration.md for full setup, entitlements, build, XPC, Tauri integration,
 * recommended provider choice, and attribution details.
 */

import Foundation
import Network
import NetworkExtension
import os.log
import Security

// MARK: - FlowEvent (serializable shape for XPC / daemon)
// Keep this in sync with the "Network Flow Event" in architecture.md and the Go daemon's
// NetworkFlowEvent / JSON unmarshaling. Use the schema for versioning.

struct FlowEvent: Codable {
    let schema: String
    let ts: String
    let flow_id: String
    let observer: String
    let pid: Int
    let ppid: Int?                 // filled by daemon from process tree model
    let process_path: String?
    let process_bundle_id: String?
    let process_team_id: String?
    let signing_info: SigningInfo?
    let local: String?
    let remote: String
    let sni: String?
    let hostname: String?
    let hostname_source: String?
    let ptr_hostname: String?
    let `protocol`: String         // "tcp" | "udp" | ...
    let direction: String          // "out" | "in"
    let bytes_out: Int
    let bytes_in: Int
    let state: String              // "new" | "established" | "closed" | ...

    struct SigningInfo: Codable {
        let team: String?
        let identifier: String?
        let path: String?
    }
}

// MARK: - XPC sender (extension -> host bridge -> daemon socket)

final class XPCEventSender {
    private var connection: NSXPCConnection?
    private var daemonSocketPath: String?
    private var xpcToken: String?
    private var logFlowEvents = false
    private let failureLogLock = NSLock()
    private var lastDirectFailureLogAt = Date.distantPast
    private var lastXPCFailureLogAt = Date.distantPast
    private var directRetryAfter = Date.distantPast
    private var xpcRetryAfter = Date.distantPast
    private let failureLogInterval: TimeInterval = 30
    private let deliveryRetryBackoff: TimeInterval = 10
    private let maxEncodedEventBytes = 32 * 1024

    // SAFETY: delivery MUST NOT happen on the flow-decision path. handleNewFlow
    // returns .allow() synchronously; the actual socket connect()/write() (which
    // can block on a wedged daemon or a full send buffer) runs here, off-path, on
    // a serial background queue. A blocked send can never stall a network verdict.
    private let deliveryQueue = DispatchQueue(label: "com.somoore.agentsnitch.flow-delivery", qos: .utility)
    // Bound the backlog so a stuck daemon cannot make the queue grow without
    // limit. Excess events are dropped (observation is best-effort); the verdict
    // path is unaffected either way.
    private let maxQueuedDeliveries = 256
    private let queueDepthLock = NSLock()
    private var queuedDeliveries = 0

    var canAttemptDelivery: Bool {
        let now = Date()
        failureLogLock.lock()
        let canAttempt = now >= directRetryAfter || now >= xpcRetryAfter
        failureLogLock.unlock()
        return canAttempt
    }

    func connect(daemonSocketPath: String?, xpcToken: String?, logFlowEvents: Bool) {
        if let previousConnection = connection {
            previousConnection.interruptionHandler = nil
            previousConnection.invalidationHandler = nil
            previousConnection.invalidate()
        }
        self.daemonSocketPath = daemonSocketPath
        self.xpcToken = xpcToken
        self.logFlowEvents = logFlowEvents
        // Outbound connection from extension to a service published by the containing app.
        // The host app is responsible for exposing this local service name.
        connection = NSXPCConnection(machServiceName: AgentSnitchXPCServiceName, options: [])
        connection?.remoteObjectInterface = NSXPCInterface(with: AgentSnitchXPCProtocol.self)
        connection?.interruptionHandler = { [weak self] in
            self?.markXPCDeliveryUnavailable()
            self?.logSendFailure(kind: "XPC connection interrupted", message: "connection interrupted")
        }
        connection?.invalidationHandler = { [weak self] in
            self?.markXPCDeliveryUnavailable()
            self?.logSendFailure(kind: "XPC connection invalidated", message: "connection invalidated")
        }
        connection?.resume()

        // Fallback / dev: we always also log.
    }

    func disconnect() {
        guard let currentConnection = connection else {
            return
        }
        currentConnection.interruptionHandler = nil
        currentConnection.invalidationHandler = nil
        currentConnection.invalidate()
        connection = nil
    }

    // send does only cheap, non-blocking work on the caller's thread (which may
    // be the flow-decision path): encode, size-check, and enqueue. The blocking
    // socket I/O is dispatched to deliveryQueue so it can never stall a verdict.
    func send(_ event: FlowEvent) {
        guard let data = try? JSONEncoder().encode(event) else {
            logToUnified(event)
            return
        }
        guard data.count <= maxEncodedEventBytes else {
            logSendFailure(kind: "event encode", message: "encoded event exceeded \(maxEncodedEventBytes) bytes")
            return
        }

        // Drop rather than grow unboundedly if the daemon is wedged. The verdict
        // path already returned .allow(); losing an observation event is benign.
        queueDepthLock.lock()
        if queuedDeliveries >= maxQueuedDeliveries {
            queueDepthLock.unlock()
            logSendFailure(kind: "delivery queue full", message: "dropped flow event (backlog >= \(maxQueuedDeliveries))")
            return
        }
        queuedDeliveries += 1
        queueDepthLock.unlock()

        deliveryQueue.async { [weak self] in
            guard let self else { return }
            defer {
                self.queueDepthLock.lock()
                self.queuedDeliveries -= 1
                self.queueDepthLock.unlock()
            }
            self.deliver(data, event: event)
        }
    }

    // deliver runs ONLY on deliveryQueue (never the flow-decision path). The
    // blocking connect()/write() here is therefore harmless to network verdicts.
    private func deliver(_ data: Data, event: FlowEvent) {
        if let daemonSocketPath {
            do {
                try UnixSocketEventSender.send(data, socketPath: daemonSocketPath)
                markDirectDeliveryAvailable()
                if logFlowEvents {
                    logToUnified(event)
                }
                return
            } catch {
                logSendFailure(kind: "direct daemon send", error: error)
                markDirectDeliveryUnavailable()
            }
        }

        if canAttemptXPCDelivery(),
           let proxy = connection?.remoteObjectProxyWithErrorHandler({ [weak self] error in
               self?.logSendFailure(kind: "XPC send", error: error)
               self?.markXPCDeliveryUnavailable()
           }) as? AgentSnitchXPCProtocol {
            let token = xpcToken ?? ""
            proxy.handleFlowEvent(data, token: token) { [weak self] ok, message in
                if !ok {
                    self?.logSendFailure(kind: "XPC receiver rejected FlowEvent", message: message ?? "(no message)")
                    self?.markXPCDeliveryUnavailable()
                }
            }
        }
        if logFlowEvents {
            logToUnified(event)
        }
    }

    private func logSendFailure(kind: String, error: Error) {
        logSendFailure(kind: kind, message: String(describing: error))
    }

    private func logSendFailure(kind: String, message: String) {
        let now = Date()
        var shouldLog = false

        failureLogLock.lock()
        if kind.hasPrefix("direct") {
            shouldLog = now.timeIntervalSince(lastDirectFailureLogAt) >= failureLogInterval
            if shouldLog {
                lastDirectFailureLogAt = now
            }
        } else {
            shouldLog = now.timeIntervalSince(lastXPCFailureLogAt) >= failureLogInterval
            if shouldLog {
                lastXPCFailureLogAt = now
            }
        }
        failureLogLock.unlock()

        if shouldLog {
            os_log("AgentSnitch %{public}@ failed: %{public}@", kind, message)
        }
    }

    private func canAttemptXPCDelivery() -> Bool {
        let now = Date()
        failureLogLock.lock()
        let canAttempt = now >= xpcRetryAfter
        failureLogLock.unlock()
        return canAttempt
    }

    private func markDirectDeliveryAvailable() {
        failureLogLock.lock()
        directRetryAfter = .distantPast
        failureLogLock.unlock()
    }

    private func markDirectDeliveryUnavailable() {
        failureLogLock.lock()
        directRetryAfter = Date().addingTimeInterval(deliveryRetryBackoff)
        failureLogLock.unlock()
    }

    private func markXPCDeliveryUnavailable() {
        failureLogLock.lock()
        xpcRetryAfter = Date().addingTimeInterval(deliveryRetryBackoff)
        failureLogLock.unlock()
    }

    private func logToUnified(_ event: FlowEvent) {
        let logger = Logger(subsystem: "com.somoore.agentsnitch.network-extension", category: "FlowEvent")
        logger.info("schema=\(event.schema) pid=\(event.pid) remote=\(event.remote) sni=\(event.sni ?? "(none)") path=\(event.process_path ?? "(unknown)") team=\(event.signing_info?.team ?? "-")")
        // For even lower level: use os_log(OS_LOG_DEFAULT, "AgentSnitchNE: ...")
    }
}

enum UnixSocketEventSender {
    // Bound every blocking socket op so a wedged daemon (alive but not draining,
    // or a full send buffer) cannot jam the delivery queue forever. Even though
    // delivery runs off the flow-decision path, an unbounded write() would stall
    // ALL future delivery on the serial queue; this caps that to sendTimeout.
    private static let sendTimeout = timeval(tv_sec: 1, tv_usec: 0)

    static func send(_ data: Data, socketPath: String) throws {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        if fd < 0 {
            throw POSIXError(.init(rawValue: errno) ?? .EIO)
        }
        defer { close(fd) }

        // SO_SNDTIMEO bounds write(); SO_RCVTIMEO is set for symmetry. A timed-out
        // op returns EAGAIN/EWOULDBLOCK and is thrown like any other send failure,
        // tripping the existing delivery-backoff logic.
        var timeout = sendTimeout
        _ = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let maxPathLength = MemoryLayout.size(ofValue: addr.sun_path)
        guard socketPath.utf8.count < maxPathLength else {
            throw POSIXError(.ENAMETOOLONG)
        }
        _ = withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            socketPath.withCString { src in
                strncpy(UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: CChar.self), src, maxPathLength)
            }
        }

        let connectResult = withUnsafePointer(to: &addr) { ptr -> Int32 in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                connect(fd, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        if connectResult != 0 {
            throw POSIXError(.init(rawValue: errno) ?? .ECONNREFUSED)
        }

        var payload = data
        payload.append(0x0a)
        try payload.withUnsafeBytes { raw in
            guard let base = raw.baseAddress else { return }
            var written = 0
            while written < payload.count {
                let n = write(fd, base.advanced(by: written), payload.count - written)
                if n < 0 {
                    throw POSIXError(.init(rawValue: errno) ?? .EIO)
                }
                written += n
            }
        }
    }
}

// MARK: - Provider Implementation (NEFilterDataProvider chosen for MVP observe simplicity)

/// The principal class for the Network Extension.
/// Registered in the extension's Info.plist under NSExtensionPrincipalClass.
final class AgentSnitchNetworkExtension: NEFilterDataProvider {

    private let sender = XPCEventSender()
    private let iso8601DateFormatter = ISO8601DateFormatter()
    private var flowIDCounter: UInt64 = 0
    private var flows: [UUID: ObservedFlow] = [:]
    private let flowLock = NSLock()
    private var attributionCache: [pid_t: ProcessAttribution] = [:]
    private let attributionLock = NSLock()
    private let peekBytes = 4096
    private let establishedEmitInterval: TimeInterval = 2.0
    private let maxDaemonSocketPathBytes = 104
    private var captureByteLifecycle = false
    private var observeLocalTraffic = false
    private var logFlowEvents = false

    private struct ObservedFlow {
        let flowID: String
        let pid: Int
        let processPath: String?
        let processBundleID: String?
        let processTeamID: String?
        let signingInfo: FlowEvent.SigningInfo?
        var local: String?
        var remote: String
        var sni: String?
        var hostname: String?
        var hostnameSource: String?
        var ptrHostname: String?
        let proto: String
        let direction: String
        var bytesOut: Int
        var bytesIn: Int
        var emittedEstablished: Bool
        var emittedClosed: Bool
        var inboundComplete: Bool
        var outboundComplete: Bool
        var lastEstablishedEmitAt: Date?
        var lastEmittedBytesOut: Int
        var lastEmittedBytesIn: Int
    }

    // Called when the system starts the filter (after activation + user approval + config).
    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        os_log("AgentSnitchNetworkExtension: startFilter (NEFilterDataProvider)")

        let daemonSocketPath = daemonSocketPathFromConfiguration()
        if let daemonSocketPath {
            os_log("AgentSnitchNetworkExtension: daemon socket configured (%d bytes)", daemonSocketPath.utf8.count)
        } else {
            os_log("AgentSnitchNetworkExtension: daemon socket missing from provider configuration")
        }

        captureByteLifecycle = filterConfiguration.vendorConfiguration?["capture_bytes"] as? Bool ?? false
        observeLocalTraffic = filterConfiguration.vendorConfiguration?["observe_local"] as? Bool ?? false
        logFlowEvents = filterConfiguration.vendorConfiguration?["log_flow_events"] as? Bool ?? false
        os_log("AgentSnitchNetworkExtension: capture byte lifecycle=%{public}@", captureByteLifecycle ? "true" : "false")

        sender.connect(daemonSocketPath: daemonSocketPath, xpcToken: xpcTokenFromConfiguration(), logFlowEvents: logFlowEvents)

        // The host bridge configures NEFilterManager with filterSockets enabled and
        // filterDataProviderBundleIdentifier set to AgentSnitchNetworkExtensionBundleID.
        // For broad "ground truth" we let the system send socket flows to this provider;
        // the daemon filters by active agent process tree.

        completionHandler(nil)
    }

    private func daemonSocketPathFromConfiguration() -> String? {
        guard let raw = filterConfiguration.vendorConfiguration?["daemon_socket"] as? String else {
            return nil
        }
        let path = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard path.hasPrefix("/") else {
            os_log("AgentSnitchNetworkExtension: rejected daemon socket config because path is not absolute")
            return nil
        }
        guard path.utf8.count < maxDaemonSocketPathBytes else {
            os_log("AgentSnitchNetworkExtension: rejected oversized daemon socket config (%d bytes)", path.utf8.count)
            return nil
        }
        return path
    }

    private func xpcTokenFromConfiguration() -> String? {
        guard let raw = filterConfiguration.vendorConfiguration?["xpc_token"] as? String else {
            return nil
        }
        let token = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard token.count >= 32 && token.count <= 128 else {
            os_log("AgentSnitchNetworkExtension: rejected invalid XPC token length")
            return nil
        }
        return token
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        os_log("AgentSnitchNetworkExtension: stopFilter reason=%d", reason.rawValue)
        sender.disconnect()
        completionHandler()
    }

    /// Main entry point for new network flows. This is where attribution lives.
    ///
    /// We ALWAYS return .allow() in the sensor/observe path (never gate or slow the agent).
    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard sender.canAttemptDelivery else {
            return .allow()
        }

        let remoteForDecision = quickRemoteString(for: flow)
        guard observeLocalTraffic || shouldObserveRemote(remoteForDecision) else {
            return .allow()
        }

        let observed = observeFlow(flow)
        storeObservedFlow(observed, for: flow)

        sender.send(makeEvent(from: observed, state: "new"))

        guard captureByteLifecycle else {
            return .allow()
        }

        // Debug-only path. Production defaults keep captureByteLifecycle false so
        // AgentSnitch never sits in the byte path for ordinary user traffic.
        return NEFilterNewFlowVerdict.filterDataVerdict(
            withFilterInbound: true,
            peekInboundBytes: peekBytes,
            filterOutbound: true,
            peekOutboundBytes: peekBytes
        )
    }

    override func handleInboundData(from flow: NEFilterFlow, readBytesStartOffset offset: Int, readBytes: Data) -> NEFilterDataVerdict {
        updateFlow(flow, inboundBytes: readBytes.count, outboundBytes: 0, state: "established")
        return NEFilterDataVerdict(passBytes: readBytes.count, peekBytes: peekBytes)
    }

    override func handleOutboundData(from flow: NEFilterFlow, readBytesStartOffset offset: Int, readBytes: Data) -> NEFilterDataVerdict {
        updateFlow(flow, inboundBytes: 0, outboundBytes: readBytes.count, state: "established")
        return NEFilterDataVerdict(passBytes: readBytes.count, peekBytes: peekBytes)
    }

    override func handleInboundDataComplete(for flow: NEFilterFlow) -> NEFilterDataVerdict {
        markFlowComplete(flow, inbound: true)
        return NEFilterDataVerdict.allow()
    }

    override func handleOutboundDataComplete(for flow: NEFilterFlow) -> NEFilterDataVerdict {
        markFlowComplete(flow, inbound: false)
        return NEFilterDataVerdict.allow()
    }

    private func observeFlow(_ flow: NEFilterFlow) -> ObservedFlow {
        flowIDCounter += 1
        let flowID = String(format: "nef-%llu-%@", flowIDCounter, String(flow.identifier.uuidString.prefix(8)))
        var pid: pid_t = -1
        var processPath: String?
        var teamID: String?
        var bundleID: String?
        var remote: String = "unknown"
        var local: String?
        var sni: String?
        var hostname: String?
        var hostnameSource: String?
        let ptrHostname: String? = nil
        var protoStr = "tcp"
        let dirStr = directionString(flow.direction)

        // === ATTRIBUTION (the key value of using NE vs userland) ===
        // Prefer sourceProcessAuditToken because it identifies the process that
        // created the flow; fall back to sourceAppAuditToken for older systems or
        // flows where process attribution is unavailable.
        if let attribution = processAttribution(for: flow) {
            pid = attribution.pid
            processPath = attribution.path
            teamID = attribution.teamID
            bundleID = attribution.bundleID
        }

        // === ENDPOINTS ===
        // NEFilterFlow gives some metadata; richer info (full 5-tuple, interface) available
        // via other properties or by requesting more data in the verdict.
        if let socketFlow = flow as? NEFilterSocketFlow {
            protoStr = protocolString(socketFlow.socketProtocol)
            if #available(macOS 15.0, *) {
                if let remoteEndpoint = networkEndpointString(socketFlow.remoteFlowEndpoint) {
                    remote = remoteEndpoint
                }
                if let localEndpoint = networkEndpointString(socketFlow.localFlowEndpoint) {
                    local = localEndpoint
                }
            }
            if #available(macOS 11.0, *) {
                hostname = hostnameHint(socketFlow.remoteHostname)
                if let hostname {
                    hostnameSource = "network_extension_remote_hostname"
                    if remote == "unknown" {
                        remote = hostname
                    }
                }
            }
        } else if !flow.description.isEmpty {
            let desc = flow.description
            remote = desc
        }

        // Local endpoint not always populated on the base flow; often available in data callbacks.
        // local = ...

        // === Destination host hint / SNI (best effort, no MITM) ===
        // remoteHostname is a sensor hostname hint, not proof that TLS SNI was observed.
        sni = nil

        let signing = (teamID != nil || bundleID != nil || processPath != nil)
            ? FlowEvent.SigningInfo(team: teamID, identifier: bundleID, path: processPath)
            : nil
        return ObservedFlow(
            flowID: flowID,
            pid: Int(pid),
            processPath: processPath,
            processBundleID: bundleID,
            processTeamID: teamID,
            signingInfo: signing,
            local: local,
            remote: remote,
            sni: sni,
            hostname: hostname,
            hostnameSource: hostnameSource,
            ptrHostname: ptrHostname,
            proto: protoStr,
            direction: dirStr,
            bytesOut: 0,
            bytesIn: 0,
            emittedEstablished: false,
            emittedClosed: false,
            inboundComplete: false,
            outboundComplete: false,
            lastEstablishedEmitAt: nil,
            lastEmittedBytesOut: 0,
            lastEmittedBytesIn: 0
        )
    }

    private func makeEvent(from observed: ObservedFlow, state: String) -> FlowEvent {
        return FlowEvent(
            schema: "agentsnitch.network.v0",
            ts: iso8601DateFormatter.string(from: Date()),
            flow_id: observed.flowID,
            observer: "network_extension",
            pid: observed.pid,
            ppid: nil,   // daemon correlates using hook PIDs + process snapshots
            process_path: observed.processPath,
            process_bundle_id: observed.processBundleID,
            process_team_id: observed.processTeamID,
            signing_info: observed.signingInfo,
            local: observed.local,
            remote: observed.remote,
            sni: observed.sni,
            hostname: observed.hostname,
            hostname_source: observed.hostnameSource,
            ptr_hostname: observed.ptrHostname,
            protocol: observed.proto,
            direction: observed.direction,
            bytes_out: observed.bytesOut,
            bytes_in: observed.bytesIn,
            state: state
        )
    }

    private func storeObservedFlow(_ observed: ObservedFlow, for flow: NEFilterFlow) {
        flowLock.lock()
        flows[flow.identifier] = observed
        flowLock.unlock()
    }

    private func updateFlow(_ flow: NEFilterFlow, inboundBytes: Int, outboundBytes: Int, state: String) {
        var eventToSend: FlowEvent?
        flowLock.lock()
        var observed = flows[flow.identifier] ?? observeFlow(flow)
        observed.bytesIn += inboundBytes
        observed.bytesOut += outboundBytes
        if shouldEmitEstablished(observed) {
            observed.emittedEstablished = true
            observed.lastEstablishedEmitAt = Date()
            observed.lastEmittedBytesOut = observed.bytesOut
            observed.lastEmittedBytesIn = observed.bytesIn
            eventToSend = makeEvent(from: observed, state: state)
        }
        flows[flow.identifier] = observed
        flowLock.unlock()

        if let eventToSend {
            sender.send(eventToSend)
        }
    }

    private func quickRemoteString(for flow: NEFilterFlow) -> String {
        if let socketFlow = flow as? NEFilterSocketFlow {
            if #available(macOS 15.0, *),
               let remoteEndpoint = networkEndpointString(socketFlow.remoteFlowEndpoint) {
                return remoteEndpoint
            }
            if #available(macOS 11.0, *),
               let hostname = hostnameHint(socketFlow.remoteHostname) {
                return hostname
            }
        }
        return "unknown"
    }

    private func shouldObserveRemote(_ remote: String) -> Bool {
        let trimmed = remote.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed != "unknown" else {
            return true
        }

        let lower = trimmed.lowercased()
        if lower == "localhost" || lower.hasSuffix(".local") {
            return false
        }

        let host = remoteHost(from: lower)
        if host.hasPrefix("127.") || host.hasPrefix("169.254.") || host.hasPrefix("192.168.") || host.hasPrefix("10.") {
            return false
        }
        if host == "0.0.0.0" || host == "255.255.255.255" || host == "::1" || host.hasPrefix("fe80:") || host.hasPrefix("ff") {
            return false
        }
        if let firstOctet = Int(host.split(separator: ".").first ?? ""), firstOctet >= 224 && firstOctet <= 239 {
            return false
        }
        if isRFC1918172Address(host) {
            return false
        }
        return true
    }

    private func remoteHost(from remote: String) -> String {
        if remote.hasPrefix("["),
           let close = remote.firstIndex(of: "]") {
            return String(remote[remote.index(after: remote.startIndex)..<close])
        }
        let parts = remote.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
        return parts.first.map(String.init) ?? remote
    }

    private func isRFC1918172Address(_ host: String) -> Bool {
        let pieces = host.split(separator: ".")
        guard pieces.count == 4,
              pieces[0] == "172",
              let second = Int(pieces[1]) else {
            return false
        }
        return second >= 16 && second <= 31
    }

    private func shouldEmitEstablished(_ observed: ObservedFlow) -> Bool {
        if !observed.emittedEstablished {
            return true
        }
        guard let last = observed.lastEstablishedEmitAt else {
            return true
        }
        return Date().timeIntervalSince(last) >= establishedEmitInterval
    }

    private func markFlowComplete(_ flow: NEFilterFlow, inbound: Bool) {
        flowLock.lock()
        guard var observed = flows[flow.identifier], !observed.emittedClosed else {
            flowLock.unlock()
            return
        }
        if inbound {
            observed.inboundComplete = true
        } else {
            observed.outboundComplete = true
        }
        guard observed.inboundComplete && observed.outboundComplete else {
            flows[flow.identifier] = observed
            flowLock.unlock()
            return
        }
        observed.emittedClosed = true
        flows.removeValue(forKey: flow.identifier)
        flowLock.unlock()

        sender.send(makeEvent(from: observed, state: "closed"))
    }

    private func directionString(_ direction: NETrafficDirection) -> String {
        switch direction {
        case .inbound:
            return "in"
        case .outbound:
            return "out"
        default:
            return "out"
        }
    }

    private func protocolString(_ socketProtocol: Int32) -> String {
        switch socketProtocol {
        case IPPROTO_UDP:
            return "udp"
        case IPPROTO_TCP:
            return "tcp"
        default:
            return "tcp"
        }
    }

    private func hostnameHint(_ value: String?) -> String? {
        guard let raw = value?.trimmingCharacters(in: .whitespacesAndNewlines),
              !raw.isEmpty else {
            return nil
        }
        let host = raw.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        guard host.contains(where: { $0.isLetter }) else {
            return nil
        }
        guard !host.contains(":"),
              !host.contains("/"),
              !host.contains(" ") else {
            return nil
        }
        return host
    }

    private struct ProcessAttribution {
        let pid: pid_t
        let path: String?
        let teamID: String?
        let bundleID: String?
    }

    private func preferredAuditTokenData(for flow: NEFilterFlow) -> Data? {
        if #available(macOS 13.0, *),
           let processToken = flow.sourceProcessAuditToken as Data? {
            return processToken
        }
        return flow.sourceAppAuditToken as Data?
    }

    private func processAttribution(for flow: NEFilterFlow) -> ProcessAttribution? {
        guard let auditData = preferredAuditTokenData(for: flow) else {
            return nil
        }

        let auditTokenPtr = auditData.withUnsafeBytes { $0.bindMemory(to: audit_token_t.self).baseAddress! }
        let auditToken = auditTokenPtr.pointee
        let pid = audit_token_to_pid(auditToken)
        if let cached = cachedAttribution(for: pid) {
            return cached
        }

        var processPath: String?
        var teamID: String?
        var bundleID: String?

        var code: SecCode?
        let guestAttrs: [String: Any] = [kSecGuestAttributeAudit as String: auditData]
        if SecCodeCopyGuestWithAttributes(nil, guestAttrs as CFDictionary, [], &code) == errSecSuccess,
           let code = code {
            var staticCode: SecStaticCode?
            if SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess,
               let staticCode = staticCode {
                var pathURL: CFURL?
                SecCodeCopyPath(staticCode, [], &pathURL)
                processPath = (pathURL as URL?)?.path

                var signingInfoRef: CFDictionary?
                if SecCodeCopySigningInformation(staticCode, [], &signingInfoRef) == errSecSuccess,
                   let signingInfo = signingInfoRef as? [String: Any] {
                    teamID = signingInfo["teamid"] as? String
                    bundleID = signingInfo[kSecCodeInfoIdentifier as String] as? String
                }
            }
        }

        let attribution = ProcessAttribution(pid: pid, path: processPath, teamID: teamID, bundleID: bundleID)
        cacheAttribution(attribution)
        return attribution
    }

    private func cachedAttribution(for pid: pid_t) -> ProcessAttribution? {
        guard pid > 0 else {
            return nil
        }
        attributionLock.lock()
        let cached = attributionCache[pid]
        attributionLock.unlock()
        return cached
    }

    private func cacheAttribution(_ attribution: ProcessAttribution) {
        guard attribution.pid > 0 else {
            return
        }
        attributionLock.lock()
        attributionCache[attribution.pid] = attribution
        attributionLock.unlock()
    }

    @available(macOS 15.0, *)
    private func networkEndpointString(_ endpoint: Network.NWEndpoint?) -> String? {
        guard let endpoint else {
            return nil
        }
        switch endpoint {
        case .hostPort(let host, let port):
            return "\(host):\(port)"
        case .service(let name, let type, let domain, _):
            let pieces = [name, type, domain].filter { !$0.isEmpty }
            return pieces.isEmpty ? nil : pieces.joined(separator: ".")
        default:
            return String(describing: endpoint)
        }
    }

    deinit {
        sender.disconnect()
    }
}
