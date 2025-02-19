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

#ifndef TEE_HILOG_LOCK_H
#define TEE_HILOG_LOCK_H

#include <stdio.h>
#include "log.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef DEF_ENG
#define TEE_LOG_MASK    0
#else
#define TEE_LOG_MASK    2
#endif

#define LOG_TAG_TEEC "tee_client"

#define TAG_VERBOSE "[VERBOSE]"
#define TAG_DEBUG   "[DEBUG]"
#define TAG_INFO    "[INFO]"
#define TAG_WARN    "[WARN]"
#define TAG_ERROR   "[ERROR]"

typedef enum {
    LOG_LEVEL_ERROR  = 0,
    LOG_LEVEL_WARN   = 1,
    LOG_LEVEL_INFO   = 2,
    LOG_LEVEL_DEBUG  = 3,
    LOG_LEVEL_VERBO  = 4,
} LOG_LEVEL;

#define tlogv(fmt, args...) \
    do { \
        if (TEE_LOG_MASK == 0) \
            HILOG_DEBUG(HILOG_MODULE_SEC, "[%s]%s " fmt, LOG_TAG_TEEC, TAG_VERBOSE, ##args); \
    } while (0)

#define tlogd(fmt, args...) \
    do { \
        if (TEE_LOG_MASK <= 1) \
            HILOG_DEBUG(HILOG_MODULE_SEC, "[%s]%s " fmt, LOG_TAG_TEEC, TAG_DEBUG, ##args); \
    } while (0)

#define tlogi(fmt, args...) \
    do { \
        if (TEE_LOG_MASK <= 2) \
            HILOG_INFO(HILOG_MODULE_SEC, "[%s]%s " fmt, LOG_TAG_TEEC, TAG_INFO, ##args); \
    } while (0)

#define tlogw(fmt, args...) \
    do { \
        if (TEE_LOG_MASK <= 3) \
            HILOG_WARN(HILOG_MODULE_SEC, "[%s]%s " fmt, LOG_TAG_TEEC, TAG_WARN, ##args); \
    } while (0)

#define tloge(fmt, args...) \
    do { \
        if (TEE_LOG_MASK <= 4) \
            HILOG_ERROR(HILOG_MODULE_SEC, "[%s]%s " fmt, LOG_TAG_TEEC, TAG_ERROR, ##args); \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif
