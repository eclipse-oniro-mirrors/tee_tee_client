# Copyright (C) 2022 Huawei Technologies Co., Ltd.
# Licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
ROOT_DIR := ../../../../../
include $(ROOT_DIR)/out/iot_config.mk
TOOLCHAIN_DIR := $(ROOT_DIR)/prebuilts/clang/ohos/linux-x86_64/llvm/bin
export CROSS_COMPILE=$(TOOLCHAIN_DIR)/aarch64-linux-ohos
ifeq ($(DEVICE_MODEL), "AGS-X20")
export SYSROOT=$(ROOT_DIR)/out/smartlock_AGS_X20$()/hi3519dv500_smartlock_small/sysroot
else ifeq ($(DEVICE_MODEL), "AGS-Q20")
export SYSROOT=$(ROOT_DIR)/out/smartlock_AGS_Q20$()/hi3519dv500_smartlock_small/sysroot
endif

CC := $(TOOLCHAIN_DIR)/aarch64-unknown-linux-ohos-clang
AR := $(TOOLCHAIN_DIR)/llvm-ar

CFLAGS  := -Wall -march=armv8-a+simd -O3 -fomit-frame-pointer -fno-exceptions -fno-asynchronous-unwind-tables -fno-unwind-tables -fstack-protector-strong
CFLAGS  += -target aarch64-linux-ohos
CFLAGS  += --sysroot=$(SYSROOT) -I$(SYSROOT)/usr/include
CFLAGS  += -flto

DEBUG ?= 0
ifeq ($(DEBUG), 1)
CFLAGS += -O0 -g
CFLAGS += -DDEBUG
endif

RM := rm -f

define rm_dirs
if [ -d "$(1)" ] ; then rmdir --ignore-fail-on-non-empty $(1) ; fi
endef