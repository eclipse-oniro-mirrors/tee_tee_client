# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
include flags.mk

# common flags
COMMON_INCLUDES := ${CURDIR}/../../interfaces/inner_api \
                   ${CURDIR}/../../frameworks/include/standard/teec_vendor \
                   ${CURDIR}/../../frameworks/include/standard \
                   ${CURDIR}/../../frameworks/include \
                   ${CURDIR}/../../frameworks/libteec_vendor \
                   ${CURDIR}/../../services/teecd/include/standard \
                   ${CURDIR}/../../services/teecd/include \
                   ${CURDIR}/../../services/authentication \
                   ${CURDIR}/../../../../../vendor/huawei/chipset_common/modules/libc_sec/include


COMMON_CFLAGS  := $(addprefix -I, $(COMMON_INCLUDES)) $(CFLAGS) -D_GNU_SOURCE \
	 -DTEE_LOG_PATH_BASE=\"/data/vendor/log\" -DTEE_LOG_SUBFOLDER=\"hisi_logs/tee\" \
	 -DDYNAMIC_SRV_FEIMA_DIR=\"/vendor/etc/passthrough/teeos/dynamic_srv\" \
	 -DDYNAMIC_DRV_FEIMA_DIR=\"/vendor/etc/passthrough/teeos/dynamic_drv\" \
	 -DLIB_TEEC_VENDOR

S_CFLAGS := -Wextra -fstack-protector-all -s -Wl,-z,relro,-z,now,-z,noexecstack \
            -fPIE -D_FORTIFY_SOURCE=2 -O2

# compile libteec.so
MAJOR_VERSION := 1
MINOR_VERSION := 0
PATCH_VERSION := 0
TARGET_LIB := libteec.so
LIB_MAJOR := $(TARGET_LIB).$(MAJOR_VERSION)
LIB_MAJ_MIN := $(TARGET_LIB).$(MAJOR_VERSION).$(MINOR_VERSION)
LIB_MAJ_MIN_P := $(TARGET_LIB).$(MAJOR_VERSION).$(MINOR_VERSION).$(PATCH_VERSION)
LIBTEEC_OUT_DIR := $(CURDIR)/out/libteec

TEEC_SRCS := frameworks/libteec_vendor/tee_client_api.c \
             frameworks/libteec_vendor/tee_client_app_load.c \
             frameworks/libteec_vendor/tee_client_socket.c \
             frameworks/libteec_vendor/load_sec_file.c \
             frameworks/tee_file/tee_file.c

TEEC_SRC_DIR := ${CURDIR}/../../
TEEC_OBJ_DIR := $(LIBTEEC_OUT_DIR)

TEEC_OBJS := $(patsubst %.c,$(TEEC_OBJ_DIR)/%.o, $(TEEC_SRCS))
TEEC_CFLAGS  := -lpthread
TEEC_CFLAGS  += -DCONFIG_ARMPC_PLATFORM -DCONFIG_AGENT_FS -DCONFIG_LOG_NO_PUBLIC
TEEC_LIBRARY := $(LIBTEEC_OUT_DIR)/$(LIB_MAJ_MIN_P)
TEEC_LIBRARY_LDFLAGS := $(CURDIR)/out/libsecurec/libsecurec.aarch64.a
ifneq ($(wildcard $(TOOLCHAIN_ROOT)/gcc-arm-10.2-2020.11-x86_64-aarch64-none-linux-gnu/bin),)
TEEC_LIBRARY_LDFLAGS += -Wl,-z,max-page-size=0x1000
TEEC_LIBRARY_LDFLAGS += -Wl,-z,separate-code
endif

# compile teecd
TARGET_APP := teecd
TEECD_OUT_DIR := $(CURDIR)/out/teecd

TEECD_SRCS := services/teecd/src/tee_agent.c \
              services/teecd/src/tee_ca_daemon.c \
              services/teecd/src/late_init_agent.c \
              services/teecd/src/misc_work_agent.c \
              services/teecd/src/fs_work_agent.c \
              services/teecd/src/secfile_load_agent.c \
              services/teecd/src/tee_load_dynamic.c \
              services/teecd/src/tee_ca_auth.c \
              services/authentication/tee_get_native_cert.c \
              services/authentication/tcu_authentication.c \
              services/authentication/tee_auth_common.c \
              frameworks/tee_file/tee_file.c

TEECD_SRC_DIR := ${CURDIR}/../../
TEECD_OBJ_DIR := $(TEECD_OUT_DIR)
TEECD_OBJS := $(patsubst %.c,$(TEECD_OBJ_DIR)/%.o, $(TEECD_SRCS))

TEECD_CFLAGS += -D_GNU_SOURCE
TEECD_CFLAGS += -DCONFIG_ARMPC_PLATFORM -DCONFIG_AGENT_FS -DCONFIG_LOG_NO_PUBLIC -DCONFIG_LATE_INIT

TEECD_FILE := $(TEECD_OUT_DIR)/$(TARGET_APP)
TEECD_LDFLAGS := -L$(TEECD_OUT_DIR)/../../libteec
TEECD_LDFLAGS += -lpthread
TEECD_LDFLAGS += -lrt
TEECD_LDFLAGS += $(CURDIR)/out/libsecurec/libsecurec.aarch64.a

# compile tlogcat
TARGET_TLOGCAT := tlogcat
TLOGCAT_OUT_DIR := $(CURDIR)/out/tlogcat/
TLOGCAT_FILES := services/tlogcat/src/tlogcat.c \
                 services/tlogcat/src/sys_syslog_cfg.c \
                 frameworks/tee_file/tee_file.c

TLOGCAT_SRC_DIR := ${CURDIR}/../../
TLOGCAT_OBJ_DIR := $(TLOGCAT_OUT_DIR)
TLOGCAT_OBJS := $(patsubst %.c,$(TLOGCAT_OBJ_DIR)/%.o, $(TLOGCAT_FILES))
TLOGCAT_FILE := $(TLOGCAT_OUT_DIR)/$(TARGET_TLOGCAT)

TLOGCAT_CFLAGS += -DCONFIG_ARMPC_PLATFORM -DCONFIG_LOG_NO_PUBLIC
TLOGCAT_CFLAGS += -DTLOGCAT_SYS_LOG
TLOGCAT_CFLAGS += -DLOG_PATH_TEE=\"/var/log/tee/\"
TLOGCAT_CFLAGS += -DLOG_PATH_BASE=\"/var/log/\"
TLOGCAT_CFLAGS += -DLOG_TMPPATH_TEE=\"/var/log/tee/_tmp/\"
TLOGCAT_CFLAGS += -DAID_SYSTEM=0
TLOGCAT_CFLAGS += -lrt
TLOGCAT_CFLAGS += -I$(CURDIR)/../../services/tlogcat/include

TLOGCAT_LDFLAGS +=  $(CURDIR)/out/libsecurec/libsecurec.aarch64.a

# compile libsecurec.aarch64.a
LIBC_OUT_DIR := $(CURDIR)/out/libsecurec
LIBC_SEC := $(LIBC_OUT_DIR)/libsecurec.aarch64.a

LIBC_FILE:= \
          vsprintf_s.c \
          wmemmove_s.c \
          strncat_s.c \
          vsnprintf_s.c \
          fwscanf_s.c \
          scanf_s.c \
          strcat_s.c \
          sscanf_s.c \
          secureprintoutput_w.c \
          wmemcpy_s.c \
          wcsncat_s.c \
          secureprintoutput_a.c \
          secureinput_w.c \
          memcpy_s.c \
          fscanf_s.c \
          vswscanf_s.c \
          secureinput_a.c \
          sprintf_s.c \
          memmove_s.c \
          swscanf_s.c \
          snprintf_s.c \
          vscanf_s.c \
          vswprintf_s.c \
          wcscpy_s.c \
          vfwscanf_s.c \
          memset_s.c \
          wscanf_s.c \
          vwscanf_s.c \
          strtok_s.c \
          wcsncpy_s.c \
          vfscanf_s.c \
          vsscanf_s.c \
          wcstok_s.c \
          securecutil.c \
          gets_s.c \
          swprintf_s.c \
          strcpy_s.c \
          wcscat_s.c \
          strncpy_s.c

LIBC_SRC_DIR := $(CURDIR)/../../../../../vendor/huawei/chipset_common/modules/libc_sec/src
LIBC_OBJ_DIR := $(LIBC_OUT_DIR)

LIBC_OBJS := $(patsubst %.c, $(LIBC_OBJ_DIR)/%.o, $(LIBC_FILE))

LIBC_INCLUDES := -I${LIBC_SRC_DIR}/../include

LIBC_CFLAGS += -D_GNU_SOURCE
LIBC_LIBRARY := $(LIBC_OUT_DIR)/libsecurec.aarch64.a

LIBC_LDFLAGS += -lpthread
LIBC_LDFLAGS += -lrt

$(LIBC_SEC): $(LIBC_OBJS)
	@echo "  AR      $@"
	$(VPREFIX)$(AR) rcs $@ $^

$(LIBC_OBJ_DIR)/%.o: $(LIBC_SRC_DIR)/%.c
	$(VPREFIX)mkdir -p $(dir $@)
	@echo "  CC      $<"
	$(VPREFIX)$(CC) $(S_CFLAGS) $(LIBC_INCLUDES) $(LIBC_LDFLAGS) -c $< -o $@

.PHONY: all clean

all: $(LIBC_SEC) $(TARGET_LIB) $(TARGET_APP) $(TARGET_TLOGCAT)
$(TARGET_APP): $(LIBC_SEC)
$(TARGET_TLOGCAT): $(LIBC_SEC)

clean: out_clean

$(TARGET_LIB): $(LIBC_SEC) $(TEEC_LIBRARY) $(LIBTEEC_OUT_DIR)/libteec.a
	$(VPREFIX)ln -sf $(LIB_MAJ_MIN_P) $(LIBTEEC_OUT_DIR)/$(LIB_MAJOR)
	$(VPREFIX)ln -sf $(LIB_MAJ_MIN_P) $(LIBTEEC_OUT_DIR)/$(LIB_MAJ_MIN)
	$(VPREFIX)ln -sf $(LIB_MAJOR) $(LIBTEEC_OUT_DIR)/$(TARGET_LIB)

$(TEEC_LIBRARY): $(TEEC_OBJS)
		@echo "  LINK      $@"
		$(VPREFIX)$(CC) $(S_CFLAGS) -shared -Wl, -soname,$(LIB_MAJOR) $(TEEC_CFLAGS) -o $@ $+ $(TEEC_LIBRARY_LDFLAGS)
		@echo ""

$(LIBTEEC_OUT_DIR)/libteec.a: $(TEEC_OBJS)
		@echo "  AR      $@"
		$(VPREFIX)$(AR) rcs $@ $+

$(TEEC_OBJ_DIR)/%.o: ${TEEC_SRC_DIR}/%.c
	$(VPREFIX)mkdir -p $(dir $@)
	@echo "  CC      $<"
	$(VPREFIX)$(CC) $(S_CFLAGS) $(COMMON_CFLAGS) $(TEEC_CFLAGS) -c $< -o $@

$(TARGET_APP): $(TEECD_FILE)

$(TEECD_FILE): $(TEECD_OBJS)
	@echo "  LINK      $@"
	$(VPREFIX)$(CC) $(S_CFLAGS) $(TEECD_CFLAGS) -o $@ $+ $(TEECD_LDFLAGS)

$(TEECD_OBJ_DIR)/%.o: $(TEECD_SRC_DIR)/%.c
	$(VPREFIX)mkdir -p $(dir $@)
	@echo "  CC      $<"
	$(VPREFIX)$(CC) $(S_CFLAGS) $(COMMON_CFLAGS) $(COMMON_INCLUDES) $(TEECD_CFLAGS) -c $< -o $@ $(TEECD_LDFLAGS)

# make tlogcat
$(TARGET_TLOGCAT): $(TLOGCAT_FILE)

$(TLOGCAT_FILE): $(TLOGCAT_OBJS)
		@echo "  LINK      $@"
		$(VPREFIX)$(CC) $(S_CFLAGS) $(TLOGCAT_CFLAGS) -o $@ $+ $(TLOGCAT_LDFLAGS)

$(TLOGCAT_OBJ_DIR)/%.o: $(TLOGCAT_SRC_DIR)/%.c
	$(VPREFIX)mkdir -p $(dir $@)
	@echo "  CC      $<"
	$(VPREFIX)$(CC) $(S_CFLAGS) $(COMMON_CFLAGS) $(COMMON_INCLUDES) $(TLOGCAT_CFLAGS) -c $< -o $@ $(TLOGCAT_LDFLAGS)

# make clean
out_clean:
	$(RM) -rf $(CURDIR)/out