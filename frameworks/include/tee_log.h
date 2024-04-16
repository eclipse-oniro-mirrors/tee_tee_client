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

#ifndef CONFIG_ARMPC_PLATFORM
#include "hilog/log_c.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "tee_client"

#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#endif
#define LOG_DOMAIN 0xD002F00

#ifndef CONFIG_ARMPC_PLATFORM
#define tlogv(...) HILOG_DEBUG(LOG_CORE, __VA_ARGS__)

#define tlogd(...) HILOG_DEBUG(LOG_CORE, __VA_ARGS__)

#define tlogi(...) HILOG_INFO(LOG_CORE, __VA_ARGS__)

#define tlogw(...) HILOG_WARN(LOG_CORE, __VA_ARGS__)

#define tloge(...) HILOG_ERROR(LOG_CORE, __VA_ARGS__)
#else
#define tlogv(...) printf(__VA_ARGS__)

#define tlogd(...) printf(__VA_ARGS__)

#define tlogi(...) printf(__VA_ARGS__)

#define tlogw(...) printf(__VA_ARGS__)

#define tloge(...) printf(__VA_ARGS__)
#endif

#ifdef __cplusplus
}
#endif

#endif
