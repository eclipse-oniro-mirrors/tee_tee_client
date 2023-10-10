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
#include <stdbool.h>
#include <hilog/log_c.h>
#include <securec.h>
#include "tee_log.h"
#include "tlogcat.h"
#include "proc_tag.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "tlogcat"

#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#endif
#define LOG_DOMAIN 0xD002F00

static char g_logItemBuffer[LOG_ITEM_MAX_LEN];

void OpenTeeLog(void)
{
}

void CloseTeeLog(void)
{
}

static void TeeHilogPrint(const struct LogItem *logItem, const char *logItemBuffer, bool isTa)
{
    uint8_t logLevel = logItem->logLevel;
    uint32_t hiLogLevel[TOTAL_LEVEL_NUMS] = {LOG_ERROR, LOG_WARN, LOG_INFO, LOG_DEBUG, LOG_DEBUG};
    const char *logTag = LOG_TEEOS_TAG;

    JudgeLogTag(logItem, isTa, &logTag);

    if (logLevel < TOTAL_LEVEL_NUMS) {
        logLevel = hiLogLevel[logLevel];
    } else {
        logLevel = LOG_INFO;
    }

    (void)HiLogPrint(LOG_CORE, logLevel, LOG_DOMAIN, logTag, "index: %{public}u: %{public}s",
        logItem->serialNo, logItemBuffer);
}

void LogWriteSysLog(const struct LogItem *logItem, bool isTa)
{
    if (logItem == NULL || logItem->logRealLen <= 0) {
        return;
    }
    if (memcpy_s(g_logItemBuffer, LOG_ITEM_MAX_LEN, logItem->logBuffer, logItem->logRealLen) == EOK) {
        g_logItemBuffer[logItem->logRealLen - 1] = '\0';
        TeeHilogPrint(logItem, (const char*)g_logItemBuffer, isTa);
    }
}