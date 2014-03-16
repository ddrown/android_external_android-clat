LOCAL_OBJ_FILES:=clatd.o dump.o checksum.o translate.o ipv4.o ipv6.o config.o dns64.o logging.o getaddr.o getroute.o netlink_callbacks.o netlink_msg.o setif.o setroute.o mtu.o __strlen_chk.o

CC=agcc
CFLAGS=-I../system_core/include/ -I../libnl-headers/

LOCAL_C_INCLUDES := external/libnl-headers
LOCAL_STATIC_LIBRARIES := libnl_2
LOCAL_SHARED_LIBRARIES := libcutils

all: clatd

clatd: $(LOCAL_OBJ_FILES)
	$(CC) -o $@ $(LOCAL_OBJ_FILES) ../system_core/libnl_2/libnl.a ../system_core/libcutils/libcutils.a ../system_core/liblog/liblog.a
