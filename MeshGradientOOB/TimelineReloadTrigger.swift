//
//  TimelineReloadTrigger.swift
//  MeshGradientOOB
//
//  PoC for CVE-2026-112691.
//

import Foundation
import OSLog
import WidgetKit

@objc(MeshGradientOOBTimelineReloadTrigger)
public final class MeshGradientOOBTimelineReloadTrigger: NSObject {
    private static let widgetKind = "com.licht.meshgradientoob.widget"
    private static let logger = Logger(subsystem: "com.licht.meshgradientoob",
                                       category: "timeline-trigger")

    /// Asks WidgetKit for a fresh timeline, which makes the extension produce
    /// and hand over a new production archive.
    @objc public static func reloadConfiguredTimeline() {
        WidgetCenter.shared.reloadTimelines(ofKind: widgetKind)
        logger.notice("MGOOB_HOST_RELOAD_REQUESTED kind=\(widgetKind, privacy: .public)")
    }
}
