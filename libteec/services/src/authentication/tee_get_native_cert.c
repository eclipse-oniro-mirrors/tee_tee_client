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

#include "tee_get_native_cert.h"
#include "securec.h"
#include "tee_client_type.h"
#include "tee_log.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG       "teecd_auth"
#define INVLIAD_PARAM (-1)

static int SetPathToBuf(uint8_t *buffer, uint32_t *len, uint32_t *inputLen, const char *path)
{
    int ret = -1;
    uint32_t num;
    uint32_t pathLen;

    num     = (uint32_t)strlen(path);
    pathLen = num;

    if (*inputLen < sizeof(pathLen)) {
        tloge("buffer overflow for pathLen\n");
        return ret;
    }

    ret = memcpy_s(buffer, *inputLen, &pathLen, sizeof(pathLen));
    if (ret != EOK) {
        tloge("copy pkgname length failed\n");
        return ret;
    }

    buffer    += sizeof(pathLen);
    *len      += sizeof(pathLen);
    *inputLen -= sizeof(pathLen);
    ret = -1;

    if (num > *inputLen) {
        tloge("buffer overflow for path\n");
        return ret;
    }

    ret = memcpy_s(buffer, *inputLen, path, num);
    if (ret != EOK) {
        tloge("copy pkgname failed\n");
        return ret;
    }

    buffer    += num;
    *len      += num;
    *inputLen -= num;

    return ret;
}

static int SetUidToBuf(uint8_t *buffer, uint32_t *len, uint32_t *inputLen, unsigned int caUid)
{
    int ret = -1;
    uint32_t pubkeyLen;

    pubkeyLen = sizeof(caUid);

    if (*inputLen < sizeof(pubkeyLen)) {
        tloge("buffer overflow for pubkeyLen\n");
        return ret;
    }

    ret = memcpy_s(buffer, *inputLen, &pubkeyLen, sizeof(pubkeyLen));
    if (ret != EOK) {
        tloge("copy uid length failed\n");
        return ret;
    }

    buffer    += sizeof(pubkeyLen);
    *len      += sizeof(pubkeyLen);
    *inputLen -= sizeof(pubkeyLen);
    ret = -1;

    if (pubkeyLen > *inputLen) {
        tloge("buffer overflow for pubkey\n");
        return ret;
    }

    ret = memcpy_s(buffer, *inputLen, &caUid, pubkeyLen);
    if (ret != EOK) {
        tloge("copy uid failed\n");
        return ret;
    }

    buffer += pubkeyLen;
    *len   += pubkeyLen;

    return ret;
}

static int SetUserInfoToBuf(uint8_t *buffer, uint32_t *len, uint32_t *inputLen, unsigned int caUid)
{
    int ret;

    ret = SetUidToBuf(buffer, len, inputLen, caUid);
    if (ret != 0) {
        tloge("set uid failed\n");
    }

    return ret;
}

int TeeGetNativeCert(int caPid, unsigned int caUid, uint32_t *len, uint8_t *buffer)
{
    int ret;
    char path[MAX_PATH_LENGTH] = { 0 };
    uint32_t inputLen;
    bool invalid = (len == NULL) || (buffer == NULL);
    if (invalid) {
        tloge("Param error!\n");
        return INVLIAD_PARAM;
    }
    inputLen = *len;

    ret = TeeGetPkgName(caPid, path, sizeof(path));
    if (ret != 0) {
        tloge("get ca path failed\n");
        return ret;
    }

    *len = 0;

    ret = SetPathToBuf(buffer, len, &inputLen, path);
    if (ret != 0) {
        tloge("set path failed\n");
        return ret;
    }
    buffer += (sizeof(uint32_t) + strlen(path));

    return SetUserInfoToBuf(buffer, len, &inputLen, caUid);
}