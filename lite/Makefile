TARGET := iphone:clang:latest:15.0
ARCHS = arm64
include $(THEOS)/makefiles/common.mk
TWEAK_NAME = SCInstaLite
SCInstaLite_FILES = ReelsOnly.xm
SCInstaLite_FRAMEWORKS = UIKit Foundation
SCInstaLite_CFLAGS = -fobjc-arc
SCInstaLite_CCFLAGS = -std=c++11
include $(THEOS_MAKE_PATH)/tweak.mk
