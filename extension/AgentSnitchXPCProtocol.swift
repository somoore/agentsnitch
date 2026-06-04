import Foundation

public let AgentSnitchXPCServiceName = "com.somoore.agentsnitch.xpc"
public let AgentSnitchNetworkExtensionBundleID = "com.somoore.agentsnitch.network-extension"

@objc(AgentSnitchXPCProtocol)
public protocol AgentSnitchXPCProtocol {
    func handleFlowEvent(_ data: Data, token: String, withReply reply: @escaping (Bool, String?) -> Void)
}
