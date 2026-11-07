//
//  ArchiveInterceptor.h
//  MeshGradientOOB
//
//  PoC for CVE-2026-112691.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Text the widget archives verbatim. The default (safe-control) rewrite
// replaces it with a same-length marker, so the rendered widget itself shows
// that the archived bytes were under widget control.
FOUNDATION_EXPORT NSString *const MGOOBControlSentinel;

NS_ASSUME_NONNULL_END
