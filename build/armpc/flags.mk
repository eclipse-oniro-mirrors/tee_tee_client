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
TOOLCHAIN_ROOT := $(ROOT_DIR)/tools/open_source/gcc-toolchains/aarch64/
TOOLCHAIN_DIR := $(TOOLCHAIN_ROOT)/gcc-linaro-7.5.0-2019.12-x86_64_aarch64-linux-gnu/bin
CC := $(TOOLCHAIN_DIR)/aarch64-linux-gnu-gcc
AR := $(TOOLCHAIN_DIR)/aarch64-linux-gnu-ar

CFLAGS := -Wall -Werror

DEBUG ?= 0
ifeq ($(DEBUG), 1)
CFLAGS += -O0 -g
CFLAGS += -DDEBUG
endif

RM := rm -f

define rm_dirs
if [ -d "$(1)" ] ; then rmdir --ignore-fail-on-non-empty $(1) ; fi
endef
