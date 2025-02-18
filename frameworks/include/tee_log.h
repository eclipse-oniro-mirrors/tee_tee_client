/*
 * Copyright (C) 2022 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#ifndef TEE_LOG_H
#define TEE_LOG_H

#ifdef CONFIG_LOG_NO_PUBLIC
#define PUBLIC ""
#else
#define PUBLIC "{public}"
#endif

#ifdef CONFIG_ARMPC_PLATFORM
#include "tee_sys_log.h"
#else
#ifdef CONFIG_SMART_LOCK_PLATFORM
#include "tee_hilog_lock.h"
#else
#include "tee_hilog.h"
#endif
#endif

#endif
