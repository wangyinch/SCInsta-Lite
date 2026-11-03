// SPDX-License-Identifier: GPL-3.0-only
// Derived from SoCuul/SCInsta 7bb71807190518ed45d21c716704c38e45a19253.
// Original authors: SoCuul and SCInsta contributors. Modified 2026-11-03.
// Only navigation, scrolling and suggested reel carousel hooks are retained.
#import <UIKit/UIKit.h>
#import <objc/runtime.h>

@interface IGMainAppSurfaceIntent : NSObject
- (NSString *)tabStringFromSurfaceIntent;
@end
@interface IGUnifiedVideoCollectionView : UIScrollView
@end

static BOOL SCIIsReelsSurface(id surface) {
    return [surface respondsToSelector:@selector(tabStringFromSurfaceIntent)] &&
        [[surface tabStringFromSurfaceIntent] isEqualToString:@"CLIPS"];
}

static NSArray *SCIFilterSurfaces(NSArray *surfaces) {
    if (![surfaces isKindOfClass:[NSArray class]]) return surfaces;
    NSMutableArray *result = [NSMutableArray arrayWithCapacity:surfaces.count];
    for (id surface in surfaces) {
        // Preserve unknown types; upstream's break could discard later tabs.
        if (!SCIIsReelsSurface(surface)) [result addObject:surface];
    }
    return [result copy];
}

%hook IGTabBarControllerSwipeCoordinator
- (id)initWithSurfaces:(id)surfaces parentViewController:(id)controller enableHaptics:(BOOL)haptics launcherSet:(id)set {
    return %orig(SCIFilterSurfaces(surfaces), controller, haptics, set);
}
%end

%hook IGTabBarController
- (void)_layoutTabBar {
    Ivar ivar = class_getInstanceVariable(object_getClass(self), "_tabBarSurfaces");
    if (ivar && ivar_getTypeEncoding(ivar)[0] == '@') {
        id surfaces = object_getIvar(self, ivar);
        if ([surfaces isKindOfClass:[NSArray class]]) {
            object_setIvarWithStrongDefault(self, ivar, SCIFilterSurfaces(surfaces));
        }
    }
    %orig;
}
- (id)_buttonForTabBarSurface:(id)surface {
    id button = %orig(surface);
    return SCIIsReelsSurface(surface) ? nil : button;
}
%end

// Do not truncate/reorder IGSundialFeedDataSource: a DM's target can be at
// a nonzero index. Leave initial positioning and all playback methods intact.
%hook IGUnifiedVideoCollectionView
- (void)didMoveToWindow {
    %orig;
    self.scrollEnabled = NO;
}
- (void)setScrollEnabled:(BOOL)enabled {
    %orig(NO);
}
%end

%hook _TtC19IGSundialAutoScroll19IGSundialAutoScroll
- (void)setIsEnabled:(BOOL)enabled {
    %orig(NO);
}
%end

%hook IGMainFeedListAdapterDataSource
- (NSArray *)objectsForListAdapter:(id)adapter {
    NSArray *original = %orig;
    Class carouselClass = objc_getClass("IGFeedScrollableClipsModel");
    if (!carouselClass || ![original isKindOfClass:[NSArray class]]) return original;
    NSMutableArray *filtered = [NSMutableArray arrayWithCapacity:original.count];
    for (id item in original) {
        if (![item isKindOfClass:carouselClass]) [filtered addObject:item];
    }
    return [filtered copy];
}
%end
