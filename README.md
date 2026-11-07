# widget-renderbox-meshgradient-oob

PoC for **CVE-2026-112691**: a controlled heap out-of-bounds write in
`RB::Fill::MeshGradient::decode` (Apple's private RenderBox framework),
reached from a normally developer-signed third-party widget through the
production WidgetKit timeline path. No private entitlement, App Group, or
special capability is involved.

Fixed in iOS 26.7.2, iOS/iPadOS 27.2, watchOS 27.2, and visionOS 27.2
(published 2026-10-26). Verified on iOS 27 beta 4 (24A5390f).

Full write-up: <https://licht-jb.github.io/posts/cve-2026-112691.html>

## How it works

```text
widget extension
  -> WidgetKit timeline request (TimelineRequest.fileHandle)
  -> promise-owned Chrono archive
  -> WidgetRenderer_Default (system process)
  -> RB::Fill::MeshGradient::decode
```

`ArchiveInterceptor.m` runs inside the widget extension. It replaces the
timeline request's file handle with a temporary file, lets the normal
archiver write the genuine archive there, rewrites the archive in place with
the same length, and returns the original completion. The system renderer
then decodes bytes chosen by the widget.

**Safe control (default build).** A text sentinel in the archive is replaced
by a same-length marker. The widget renders the marker; nothing else happens.

**Positive (`-DMGOOB_POSITIVE=1`).** The widget archives a 2x2 MeshGradient
(4 colors), which occupies exactly 70 bytes in the archive. The interceptor
replaces it byte-for-byte with a type 6 record carrying three points but
five color qwords:

```text
E = floor(5 / 3) = 1 element
allocation = 0x10 + (3 + 3) * 8 = 0x40 bytes
color span = 3 qwords, copy = 5 qwords
overflow   = A+0x40 .. A+0x4f, two archive-chosen qwords
```

RenderBox validates and allocates from the floor-divided count but copies the
original count, so the last two qwords land past the allocation. On a
vulnerable build the renderer traps shortly after; in allocator-integrity
reports the second qword is visible in `x13`.

With `-DMGOOB_ASB_TARGET=1` the second qword is the current boot's
`_COMM_PAGE_ASB_TARGET_VALUE` (Apple's published Target Flags value), so the
`x13` content is directly checkable in the crash report.

## Build

Requires a device on a vulnerable build (anything before 26.7.2 / 27.2) with
Developer Mode enabled. Signing is automatic; set your team in both targets.

```sh
# safe control first
xcodebuild -project MeshGradientOOB.xcodeproj -scheme MeshGradientOOB \
  -configuration Debug -sdk iphoneos -destination 'id=<UDID>' build

# positive
xcodebuild -project MeshGradientOOB.xcodeproj -scheme MeshGradientOOB \
  -configuration Debug -sdk iphoneos -destination 'id=<UDID>' \
  'OTHER_CFLAGS=$(inherited) -DMGOOB_POSITIVE=1 -DMGOOB_ASB_TARGET=1' build
```

## Run

1. Install the safe-control build, launch the app once, and add the
   **MeshGradientOOB** widget to the Home Screen. The widget shows
   `MGOOB_SENTINEL_...` text.
2. Launch the app again. The extension logs `MGOOB_RESULT MARKER_WRITTEN`
   (Console.app, subsystem `com.licht.meshgradientoob.widget`) and the widget
   shows `MGOOB_SAFE_MARKER_...` instead of the sentinel.
3. Install the positive build over it and launch the app once. The extension
   logs `MGOOB_RESULT OOB_PAYLOAD_WRITTEN`.
4. New `WidgetRenderer_Default` crash reports appear within about a minute
   (Settings > Privacy & Security > Analytics Data). In the ARM thread state,
   `x13` equals the logged qword (the Target Flags value in ASB mode). The
   heap layout is schedule-dependent; launch the app again if nothing appears
   within 60 seconds.
5. Cleanup: reinstall the safe build, remove the widget, uninstall the app.

`evidence/` holds four `WidgetRenderer_Default` crash reports: two from the
original report (iOS 27 beta 4) and two produced by this repository's PoC on
stock iOS 27.0.1 (24A446). All four trap in
`_xzm_xzone_malloc_freelist_outlined` with the boot's Target Flags value in
full in `x13`.

## References

- Write-up: <https://licht-jb.github.io/posts/cve-2026-112691.html>
- Advisories: [iOS 27.2](https://support.apple.com/en-us/149230) ·
  [iOS 26.7.2](https://support.apple.com/en-us/149227) ·
  [watchOS 27.2](https://support.apple.com/en-us/149525) ·
  [visionOS 27.2](https://support.apple.com/en-us/149526)
- Apple Target Flags: <https://security.apple.com/bounty/target-flags/>

Found and reported by [@Licht_jb](https://x.com/Licht_jb), July 2026.

## License

MIT. See [LICENSE](LICENSE).
