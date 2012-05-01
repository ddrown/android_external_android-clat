LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES:=clatd.c dump.c checksum.c translate.c ipv4.c ipv6.c config.c dns64.c logging.c getaddr.c netlink_callbacks.c netlink_msg.c setif.c setroute.c mtu.c

LOCAL_C_INCLUDES := external/libnl-headers
LOCAL_STATIC_LIBRARIES := libnl_2
LOCAL_SHARED_LIBRARIES := libcutils

LOCAL_MODULE_TAGS := optional

LOCAL_MODULE := clatd

include $(BUILD_EXECUTABLE)
