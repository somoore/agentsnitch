import Foundation
import Darwin
import NetworkExtension
import SystemExtensions

let defaultDaemonSocketPath = "\(NSHomeDirectory())/.agentsnitch/events.sock"
private var sharedAgentSnitchHostBridge: AgentSnitchHostBridge?

@discardableResult
private func ensureSharedAgentSnitchHostBridge() -> AgentSnitchHostBridge {
    if let bridge = sharedAgentSnitchHostBridge {
        return bridge
    }
    let bridge = AgentSnitchHostBridge()
    sharedAgentSnitchHostBridge = bridge
    return bridge
}

@_cdecl("AgentSnitchHostBridgeStart")
public func AgentSnitchHostBridgeStart() -> Int32 {
    let bridge = ensureSharedAgentSnitchHostBridge()
    bridge.start()
    return 0
}

@_cdecl("AgentSnitchHostBridgeActivateSystemExtension")
public func AgentSnitchHostBridgeActivateSystemExtension() -> Int32 {
    let bridge = ensureSharedAgentSnitchHostBridge()
    DispatchQueue.main.async {
        bridge.activateSystemExtension()
    }
    return 0
}

@_cdecl("AgentSnitchHostBridgeSetNetworkSensorDisabled")
public func AgentSnitchHostBridgeSetNetworkSensorDisabled(_ disabled: Int32) -> Int32 {
    let bridge = ensureSharedAgentSnitchHostBridge()
    let semaphore = DispatchSemaphore(value: 0)
    var succeeded = false
    let work = {
        bridge.setNetworkSensorDisabled(disabled != 0) { ok in
            succeeded = ok
            semaphore.signal()
        }
    }
    if Thread.isMainThread {
        work()
    } else {
        DispatchQueue.main.async(execute: work)
    }
    if semaphore.wait(timeout: .now() + .seconds(8)) == .timedOut {
        NSLog("AgentSnitch Network Sensor %@ timed out", disabled != 0 ? "disable" : "enable")
        return 2
    }
    return succeeded ? 0 : 1
}

public final class AgentSnitchHostBridge: NSObject {
    private let daemonSocketPath: String
    private let xpcToken: String
    private let activator: AgentSnitchSystemExtensionActivator
    private let filterConfigurator: AgentSnitchFilterConfigurator
    private var listener: NSXPCListener?
    private var exportedObject: AgentSnitchXPCReceiver?

    public override convenience init() {
        self.init(daemonSocketPath: ProcessInfo.processInfo.environment["AGENTSNITCH_SOCK"] ?? defaultDaemonSocketPath)
    }

    public init(daemonSocketPath: String) {
        self.daemonSocketPath = daemonSocketPath
        self.xpcToken = AgentSnitchHostBridge.makeXpcToken()
        self.filterConfigurator = AgentSnitchFilterConfigurator(daemonSocketPath: daemonSocketPath, xpcToken: xpcToken)
        self.activator = AgentSnitchSystemExtensionActivator()
        super.init()
        self.activator.onActivationFinished = { [weak self] in
            self?.configureFilter()
        }
    }

    public func start() {
        startXPCListener()
        configureFilter()
    }

    public func activateSystemExtension() {
        activator.activate()
    }

    public func setNetworkSensorDisabled(_ disabled: Bool, completion: @escaping (Bool) -> Void = { _ in }) {
        if disabled {
            filterConfigurator.disable(completion: completion)
        } else {
            configureFilter(completion: completion)
        }
    }

    private func configureFilter(completion: @escaping (Bool) -> Void = { _ in }) {
        guard ProcessInfo.processInfo.environment["AGENTSNITCH_DISABLE_NETWORK_EXTENSION"] != "1" else {
            NSLog("AgentSnitch Network Extension configuration skipped: AGENTSNITCH_DISABLE_NETWORK_EXTENSION=1")
            filterConfigurator.disable(completion: completion)
            return
        }
        filterConfigurator.enable(completion: completion)
    }

    private func startXPCListener() {
        let receiver = AgentSnitchXPCReceiver(daemonSocketPath: daemonSocketPath, expectedToken: xpcToken)
        let listener = NSXPCListener(machServiceName: AgentSnitchXPCServiceName)
        listener.delegate = receiver
        listener.resume()
        self.exportedObject = receiver
        self.listener = listener
        NSLog("AgentSnitchHostBridge listening on XPC service %@", AgentSnitchXPCServiceName)
    }

    private static func makeXpcToken() -> String {
        return UUID().uuidString + UUID().uuidString.replacingOccurrences(of: "-", with: "")
    }
}

public final class AgentSnitchSystemExtensionActivator: NSObject, OSSystemExtensionRequestDelegate {
    public var onActivationFinished: (() -> Void)?

    public func activate() {
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: AgentSnitchNetworkExtensionBundleID,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
    }

    public func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        NSLog("AgentSnitch system extension activation finished: %ld", result.rawValue)
        onActivationFinished?()
    }

    public func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        NSLog("AgentSnitch system extension activation failed: %@", String(describing: error))
    }

    public func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        NSLog("AgentSnitch system extension activation needs user approval")
    }

    public func request(_ request: OSSystemExtensionRequest, actionForReplacingExtension existing: OSSystemExtensionProperties, withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        return .replace
    }
}

public final class AgentSnitchFilterConfigurator {
    private let daemonSocketPath: String
    private let xpcToken: String

    init(daemonSocketPath: String, xpcToken: String) {
        self.daemonSocketPath = daemonSocketPath
        self.xpcToken = xpcToken
    }

    public func enable(completion: @escaping (Bool) -> Void = { _ in }) {
        guard daemonSocketAcceptsConnections() else {
            NSLog("AgentSnitch content filter enable skipped: daemon socket is not reachable at %@", daemonSocketPath)
            completion(false)
            return
        }

        let manager = NEFilterManager.shared()
        manager.loadFromPreferences { [daemonSocketPath, xpcToken] error in
            if let error = error {
                NSLog("AgentSnitch NEFilterManager load failed: %@", String(describing: error))
                completion(false)
                return
            }

            let config = NEFilterProviderConfiguration()
            config.filterSockets = true
            config.filterPackets = false
            config.filterDataProviderBundleIdentifier = AgentSnitchNetworkExtensionBundleID
            config.vendorConfiguration = [
                "mode": "observe",
                "daemon_socket": daemonSocketPath,
                "xpc_token": xpcToken,
                "capture_bytes": false,
                "observe_local": false,
                "log_flow_events": false,
            ]
            config.serverAddress = "AgentSnitch Local Sensor"
            config.organization = "AgentSnitch"

            manager.providerConfiguration = config
            manager.localizedDescription = "AgentSnitch local AI agent network sensor"
            manager.isEnabled = true
            if #available(macOS 10.15, *) {
                manager.grade = .inspector
            }

            manager.saveToPreferences { error in
                if let error = error {
                    NSLog("AgentSnitch NEFilterManager save failed: %@", String(describing: error))
                    completion(false)
                    return
                }
                NSLog("AgentSnitch content filter enabled for %@", AgentSnitchNetworkExtensionBundleID)
                completion(true)
            }
        }
    }

    // disable tears the content filter down. It is the user's escape hatch, so it
    // must not silently no-op: if loading prefs fails we still attempt to disable
    // (a load error may just mean no config exists, in which case the filter is
    // already down), and we verify isEnabled == false after saving.
    public func disable(completion: @escaping (Bool) -> Void = { _ in }) {
        let manager = NEFilterManager.shared()
        manager.loadFromPreferences { error in
            if let error = error {
                NSLog("AgentSnitch NEFilterManager load for disable failed (continuing to force-disable): %@", String(describing: error))
            }

            // If there is genuinely no configuration, the filter is already gone.
            guard manager.providerConfiguration != nil || manager.isEnabled else {
                NSLog("AgentSnitch content filter already absent; nothing to disable")
                completion(true)
                return
            }

            manager.isEnabled = false
            manager.saveToPreferences { error in
                if let error = error {
                    NSLog("AgentSnitch content filter disable FAILED — remove it manually via System Settings > Network > Filters: %@", String(describing: error))
                    completion(false)
                    return
                }
                if manager.isEnabled {
                    NSLog("AgentSnitch content filter still reports enabled after disable — remove it via System Settings > Network > Filters")
                    completion(false)
                } else {
                    NSLog("AgentSnitch content filter disabled")
                    completion(true)
                }
            }
        }
    }

    private func daemonSocketAcceptsConnections() -> Bool {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        if fd < 0 {
            return false
        }
        defer { close(fd) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let maxPathLength = MemoryLayout.size(ofValue: addr.sun_path)
        guard daemonSocketPath.utf8.count < maxPathLength else {
            return false
        }
        _ = withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            daemonSocketPath.withCString { src in
                strncpy(UnsafeMutableRawPointer(ptr).assumingMemoryBound(to: CChar.self), src, maxPathLength)
            }
        }

        return withUnsafePointer(to: &addr) { ptr -> Bool in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPtr in
                connect(fd, sockaddrPtr, socklen_t(MemoryLayout<sockaddr_un>.size)) == 0
            }
        }
    }
}

public final class AgentSnitchXPCReceiver: NSObject, NSXPCListenerDelegate, AgentSnitchXPCProtocol {
    private let daemonSocketPath: String
    private let expectedToken: String
    private let maxForwardedEventBytes = 32 * 1024

    init(daemonSocketPath: String, expectedToken: String) {
        self.daemonSocketPath = daemonSocketPath
        self.expectedToken = expectedToken
        super.init()
    }

    public func listener(_ listener: NSXPCListener, shouldAcceptNewConnection newConnection: NSXPCConnection) -> Bool {
        newConnection.exportedInterface = NSXPCInterface(with: AgentSnitchXPCProtocol.self)
        newConnection.exportedObject = self
        newConnection.resume()
        return true
    }

    public func handleFlowEvent(_ data: Data, token: String, withReply reply: @escaping (Bool, String?) -> Void) {
        guard !expectedToken.isEmpty && token == expectedToken else {
            reply(false, "unauthorized FlowEvent sender")
            return
        }
        guard data.count <= maxForwardedEventBytes else {
            reply(false, "FlowEvent exceeded \(maxForwardedEventBytes) bytes")
            return
        }
        do {
            try forwardToDaemon(data)
            reply(true, nil)
        } catch {
            reply(false, String(describing: error))
        }
    }

    private func forwardToDaemon(_ data: Data) throws {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        if fd < 0 {
            throw POSIXError(.init(rawValue: errno) ?? .EIO)
        }
        defer { close(fd) }

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let maxPathLength = MemoryLayout.size(ofValue: addr.sun_path)
        guard daemonSocketPath.utf8.count < maxPathLength else {
            throw POSIXError(.ENAMETOOLONG)
        }
        _ = withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            daemonSocketPath.withCString { src in
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
