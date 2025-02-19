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
#ifndef CONFIG_SMART_LOCK_PLATFORM
#include <hilog/log_c.h>
#endif
#include <securec.h>
#include "tee_log.h"
#include "tlogcat.h"
#include "proc_tag.h"

static char g_logItemBuffer[LOG_ITEM_MAX_LEN];
void OpenTeeLog(void)
{
}

void CloseTeeLog(void)
{
}

#ifndef CONFIG_SMART_LOCK_PLATFORM
#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "tlogcat"

#define LOG_DOMAIN_TEEOS 0xD005B01
#define LOG_DOMAIN_PLATDRV 0xD005BFE
#define LOG_DOMAIN_UNKNOWN 0x5BFF

typedef struct LogDomain {
    uint32_t domain;
    char uuid[UUID_MAX_STR_LEN];
} LogDomain;

const static LogDomain g_log_domain_info[] = {
    {0x5B01, "A0F02C44F7A5469194C498565A44D934"}, /* TEE_CODE_PROTECT */
    {0x5B02, "5FCE3EA5FA714152A30FF46BE8C924BF"}, /* TA_HuaweiNfcActiveCard */
    {0x5B03, "6F4EAE1E2EC249678B6875554F36E8FA"}, /* facerecognize_algo */
    {0x5B04, "49FBC428AF4411ECB9090242AC120002"}, /* HUKS */
    {0x5B05, "1074B0CA3EFB42C9AB6378711E542B1B"}, /* task_permservice */
    {0x5B06, "A3A7796FD071475B918B6E0C71316069"}, /* TEE_USER_AUTH */
    {0x5B07, "D77C4D60D2794425AFA87F94559EAE16"}, /* FIAE */
    {0x5B08, "D902F26F71534E46A79C94844AF8B007"}, /* task_vltmm_service */
    {0x5B09, "DCA5AE8A769E4E24896B7D06442C1C0E"}, /* task_secisp */
    {0x5B0A, "E8014913E5014D44A9D6058EC3B93B90"}, /* TEE_FACE_AUTH */
    {0x5B0B, "F4A8816DB6FB4D4FA2B97DAE573313C0"}, /* ai */
    {0x5B0C, "54FF868F0D8D44959D958E24B2A08274"}, /* task_file_encry */
    {0x5B0D, "86310D18565947C9B212841A3CA4F814"}, /* HW_DCM */
    {0x5B0E, "A423E43DABFD441FB89D39E39F3D7F65"}, /* TEE_FINGERPRINT_AUTH */
    {0x5B0F, "EBEED547CF6A4592B0F12AE4A8CD43DA"}, /* TEE_PIN_AUTH */
    {0x5B10, "FD1BBFB29A624B278FDBA503529076AF"}, /* TA_SensorInfo */
    {0x5B11, "95B9AD1E0AF8420198910DBE8602F35F"}, /* CHINADRM_COMMON_TA */
    {0x5B12, "A32B3D00CB5711E39C1A0800200C9A66"}, /* TEE_FINGERPRINT_AUTH-2 */
    {0x5B13, "4AE7BA5128104CEEABBEA42307B4ACE3"}, /* TA_HuaweiWallet */
    {0x5B14, "4D06A2AAD05A46F4AD58DE2D758070C9"}, /* TA_activation_lock */
    {0x5B15, "9DB3A5C655F643AE8DAD6F4BF9FDBA55"}, /* trusted_ring_service */
    {0x5B16, "C123C6435B5B4C9F9098BB09564D6EDA"}, /* ai_security */
    {0x5B18, "ABE89147CD61F43F71C41A317E405312"}, /* vsim_sw */
    {0x5B19, "2F4A54A12B3D4EC7914EC4F770905F7A"}, /* task_sec_auth */
    {0x5B1A, "7E60394321226F7990D0B2D8A7801025"}, /* dstb_service */
    {0x5B1B, "9FC2B7115FFA43909C457A1AF90F99AE"}, /* dstb_mgr_agent */
    {0x5B1C, "B2733D6C3DE54BAE8BD955A2C528B6AA"}, /* task_dev_secinfo_auth */
    {0x5B1D, "F8028DCAABA011E680F576304DEC7EB7"}  /* secmem */
};
const static uint32_t g_log_domain_info_size = sizeof(g_log_domain_info) / sizeof(g_log_domain_info[0]);

static uint32_t TeeGetTaLogDomain(struct TeeUuid *uuid)
{
    char uuidAscii[UUID_MAX_STR_LEN] = {0};
    uint32_t i;

    GetUuidStr(uuid, uuidAscii, sizeof(uuidAscii));
    for (i = 0; i < g_log_domain_info_size; i++) {
        if (strcmp(uuidAscii, g_log_domain_info[i].uuid) == 0) {
            return g_log_domain_info[i].domain;
        }
    }
    return LOG_DOMAIN_UNKNOWN;
}

static uint32_t TeeGetTeeosOrPlatdrvLogDomain(uint8_t logSourceType, const char *logItemBuffer, uint16_t bufferLen)
{
    uint16_t i;
    const char *drvTag = "platdrv";
    const uint16_t drvTagLen = strlen(drvTag);

    if (logSourceType != 0) {
        return LOG_DOMAIN_PLATDRV;
    }

    for (i = 0; i < bufferLen; i++) {
        if (logItemBuffer[i] == '[') {
            break;
        }
    }

    if ((bufferLen - i > drvTagLen) && (strncmp(&logItemBuffer[i + 1], drvTag, drvTagLen) == 0)) {
        return LOG_DOMAIN_PLATDRV;
    }

    return LOG_DOMAIN_TEEOS;
}

static void TeeHilogPrint(const struct LogItem *logItem, const char *logItemBuffer, bool isTa)
{
    uint8_t logLevel = logItem->logLevel;
    uint32_t hiLogLevel[TOTAL_LEVEL_NUMS] = {LOG_ERROR, LOG_WARN, LOG_INFO, LOG_DEBUG, LOG_DEBUG};
    const char *logTag = LOG_TEEOS_TAG;
    uint32_t log_domain;
    uint32_t log_type;

    if (isTa) {
        log_type = LOG_APP;
        log_domain = TeeGetTaLogDomain((struct TeeUuid *)logItem->uuid);
    } else {
        log_type = LOG_CORE;
        log_domain = TeeGetTeeosOrPlatdrvLogDomain(logItem->logSourceType, logItemBuffer, logItem->logRealLen);
    }

    JudgeLogTag(logItem, isTa, &logTag);

    if (logLevel < TOTAL_LEVEL_NUMS) {
        logLevel = hiLogLevel[logLevel];
    } else {
        logLevel = LOG_INFO;
    }

    HILOG_IMPL(log_type, logLevel, log_domain, logTag, "index: %{public}u: %{public}s",
        logItem->serialNo, logItemBuffer);
}
#else
static void TeeHilogPrint(const struct LogItem *logItem, const char *logItemBuffer, bool isTa)
{
    (void)isTa;
    switch (logItem->logLevel) {
        case LOG_LEVEL_ERROR:
            HILOG_ERROR(HILOG_MODULE_SEC, "[%s] index: %u: %s",
                LOG_TEEOS_TAG, logItem->serialNo, logItemBuffer);
            break;
        case LOG_LEVEL_WARN:
            HILOG_WARN(HILOG_MODULE_SEC, "[%s] index: %u: %s",
                LOG_TEEOS_TAG, logItem->serialNo, logItemBuffer);
            break;
        case LOG_LEVEL_INFO:
            HILOG_INFO(HILOG_MODULE_SEC, "[%s] index: %u: %s",
                LOG_TEEOS_TAG, logItem->serialNo, logItemBuffer);
            break;
        case LOG_LEVEL_DEBUG:
        case LOG_LEVEL_VERBO:
            HILOG_DEBUG(HILOG_MODULE_SEC, "[%s] index: %u: %s",
                LOG_TEEOS_TAG, logItem->serialNo, logItemBuffer);
            break;
        default:
            HILOG_INFO(HILOG_MODULE_SEC, "[%s] index: %u: %s",
                LOG_TEEOS_TAG, logItem->serialNo, logItemBuffer);
            break;
    }
}
#endif

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
