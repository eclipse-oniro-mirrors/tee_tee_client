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
COMMON_INCLUDES := ${CURDIR}/../../interfaces/kits/c/include \
                   ${CURDIR}/../../services/teecd/include \
                   ${CURDIR}/../../services/teecd/include/standard \
                   ${CURDIR}/../../services/authentication \
                   ${CURDIR}/../../frameworks/include/standard/teec_vendor \
                   ${CURDIR}/../../frameworks/include/standard \
                   ${CURDIR}/../../frameworks/include \
                   ${CURDIR}/../../frameworks/libteec_vendor \
                   ${CURDIR}/../../../third_party_bounds_checking_function/include
COMMON_CFLAGS := $(addprefix -I, $(COMMON_INCLUDES)) $(CFLAGS) -D_GNU_SOURCE \
				 -DTEE_LOG_PATH_BASE=\"/var/log\" -DLIB_TEEC_VENDOR -DCONFIG_TEE_PRIVATE_LOGFILE

S_CFLAGS := -Wextra -fstack-protector-all -s -Wl,-z,relro,-z,now,-z,noexecstack \
			-fPIE -D_FORTIFY_SOURCE=2 -O2

# compile teecd
TARGET_APP := teecd
TEECD_OUT_DIR := $(CURDIR)/out/teecd

TEECD_SRCS := services/teecd/src/tee_agent.c \
			  services/teecd/src/tee_ca_daemon.c \
			  services/teecd/src/late_init_agent.c \
			  services/teecd/src/misc_work_agent.c \
			  services/teecd/src/fs_work_agent.c \
			  services/teecd/src/secfile_load_agent.c \
			  services/teecd/src/tee_load_dynamic_drv.c \
			  services/teecd/src/tee_ca_auth.c \
			  services/authentication/tee_get_native_cert.c \
			  services/authentication/tcu_authentication.c \
			  services/authentication/tee_auth_common.c

TEECD_SRC_DIR := ${CURDIR}/../../
TEECD_OBJ_DIR := $(TEECD_OUT_DIR)
TEECD_OBJS := $(patsubst %.c,$(TEECD_OBJ_DIR)/%.o,$(TEECD_SRCS))

TEECD_CFLAGS += -D_GNU_SOURCE
TEECD_CFLAGS += -DCONFIG_ARMPC_PLATFORM -DCONFIG_AGENT_FS

TEECD_FILE := $(TEECD_OUT_DIR)/$(TARGET_APP)
TEECD_LDFLAGS := -L$(TEECD_OUT_DIR)/../../libteec
TEECD_LDFLAGS += -lpthread
TEECD_LDFLAGS += -lrt
TEECD_LDFLAGS += $(CURDIR)/out/libsecurec/libsecurec.aarch64.a

# compile libsecurec.aarch64.a
LIBC_OUT_DIR := $(CURDIR)/out/libsecurec
LIBC_SEC := $(LIBC_OUT_DIR)/libsecurec.aarch64.a

LIBC_FILE := vsprintf_s.c \
		      wmemmove_s.c \
			  strncat_s.c \
			  vsnprintf_s.c \
			  fwscanf_s.c \
			  scanf_s.c	\
			  strcat_s.c	\
			  sscanf_s.c	\
			  secureprintoutput_w.c	\
			  wmemcpy_s.c	\
			  wcsncat_s.c	\
			  secureprintoutput_a.c	\
			  secureinput_w.c	\
			  memcpy_s.c	\
			  fscanf_s.c	\
			  vswscanf_s.c	\
			  secureinput_a.c	\
			  sprintf_s.c	\
			  memmove_s.c	\
			  swscanf_s.c	\
			  snprintf_s.c	\
			  vscanf_s.c	\
			  vswprintf_s.c	\
			  wcscpy_s.c	\
			  vfwscanf_s.c	\
			  memset_s.c	\
			  wscanf_s.c	\
			  vwscanf_s.c	\
			  strtok_s.c	\
			  wcsncpy_s.c	\
			  vfscanf_s.c	\
			  vsscanf_s.c	\
			  wcstok_s.c	\
			  securecutil.c	\
			  gets_s.c	\
			  swprintf_s.c	\
			  strcpy_s.c	\
			  wcscat_s.c	\
			  strncpy_s.c

LIBC_SRC_DIR := $(CURDIR)/../../../third_party_bounds_checking_function/src
LIBC_OBJ_DIR:= $(LIBC_OUT_DIR)

LIBC_OBJS := $(patsubst %.c, $(LIBC_OBJ_DIR)/%.o, $(LIBC_FILE))

LIBC_INCLUDES := -I${LIBC_SRC_DIR}/../include

LIBC_CFLAGS += -D_GNU_SOURCE
LIBC_LIBRARY := $(LIBC_OUT_DIR)/libsecurec.aarch64.a

LIBC_LDFLAGS += -lpthread
LIBC_LDFLAGS += -lrt

$(LIBC_SEC): $(LIBC_OBJS)
	@echo " AR $@"
	$(VPREFIX)$(AR) rcs $@ $^

$(LIBC_OBJ_DIR)/%.o: $(LIBC_SRC_DIR)/%.c
	$(VPREFIX)mkdir -p $(dir $@)
	@echo " CC $<"
	$(VPREFIX)$(CC) $(S_CFLAGS) $(LIBC_INCLUDES) $(LIBC_LDFLAGS) -c $< -o $@

.PHONY: all clean

all: $(LIBC_SEC) $(TARGET_APP)
$(TARGET_APP): $(LIBC_SEC)

clean: out_clean

$(TARGET_APP):$(TEECD_FILE)

$(TEECD_FILE):$(TEECD_OBJS)
	@echo " LINK $@"
	$(VPREFIX)$(CC) $(S_CFLAGS) $(TEECD_CFLAGS) -o $@ $+ $(TEECD_LDFLAGS)

$(TEECD_OBJ_DIR)/%.o: $(TEECD_SRC_DIR)/%.c
	$(VPREFIX)mkdir -p $(dir $@)
	@echo " CC $<"
	$(VPREFIX)$(CC) $(S_CFLAGS) $(COMMON_CFLAGS) $(COMMON_INCLUDES) $(TEECD_CFLAGS) -c $< -o $@ $(TEECD_LDFLAGS)

# make clean
out_clean:
	$(RM) -rf $(CURDIR)/out
			  
