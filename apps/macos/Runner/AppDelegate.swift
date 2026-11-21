import Cocoa
import FlutterMacOS

@main
class AppDelegate: FlutterAppDelegate {
  override func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
    if NativeSigner.awaitingRecoveryAcknowledgment { return .terminateCancel }
    return super.applicationShouldTerminate(sender)
  }

  // Associated-domain HTTPS links only. The channel keeps a claim for the pinned coordinator and
  // the wallet shows it in Join after unlock; a link never pairs, joins or approves anything.
  override func application(_ application: NSApplication, continue userActivity: NSUserActivity,
                   restorationHandler: @escaping ([any NSUserActivityRestoring]) -> Void) -> Bool {
    if userActivity.activityType == NSUserActivityTypeBrowsingWeb, let url = userActivity.webpageURL {
      return WalletChannel.receive(url)
    }
    return super.application(application, continue: userActivity, restorationHandler: restorationHandler)
  }

  override func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
    return true
  }

  override func applicationSupportsSecureRestorableState(_ app: NSApplication) -> Bool {
    return true
  }
}
