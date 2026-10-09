// AgentACL.app: asks macOS to activate (or remove) the AgentACL Endpoint
// Security system extension, which is agentacl-esd packaged as
// Contents/Library/SystemExtensions/ai.agentacl.app.esd.systemextension.
//
//   AgentACL.app/Contents/MacOS/AgentACL activate | deactivate
//
// macOS then asks the user to allow the extension (System Settings), and
// Full Disk Access must be granted to it. Production builds need Developer
// ID signing with Apple-provisioned entitlements; see
// docs/design/endpoint-security.md.
import Foundation
import SystemExtensions

let extensionID = "ai.agentacl.app.esd"

final class Delegate: NSObject, OSSystemExtensionRequestDelegate {
    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        print("Replacing \(existing.bundleShortVersion) with \(ext.bundleShortVersion)")
        return .replace
    }
    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        print("Waiting for approval: System Settings → General → Login Items & Extensions → Endpoint Security Extensions → allow AgentACL.")
    }
    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        print(result == .completed ? "Done." : "Done; a restart completes it.")
        exit(0)
    }
    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        print("Failed: \(error.localizedDescription)")
        exit(1)
    }
}

let args = CommandLine.arguments.dropFirst()
let delegate = Delegate()
let request: OSSystemExtensionRequest
switch args.first {
case "activate":
    request = .activationRequest(forExtensionWithIdentifier: extensionID, queue: .main)
case "deactivate":
    request = .deactivationRequest(forExtensionWithIdentifier: extensionID, queue: .main)
default:
    print("usage: AgentACL activate | deactivate")
    exit(2)
}
request.delegate = delegate
OSSystemExtensionManager.shared.submitRequest(request)
dispatchMain()
