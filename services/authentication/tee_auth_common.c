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

#include "tee_auth_common.h"
#include <securec.h>
#include <stdbool.h>
#include "tee_log.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "teecd_auth"

static int ReadCmdLine(const char *path, char *buffer, size_t bufferLen, char *caName, size_t nameLen)
{
    FILE *fd = fopen(path, "rb");
    if (fd == NULL) {
        tloge("fopen is error: %d\n", errno);
        return -1;
    }
    int bytesRead = (int)fread(buffer, sizeof(char), bufferLen - 1, fd);
    bool readError = (bytesRead <= 0 || (ferror(fd) != 0));
    if (readError) {
        tloge("cannot read from cmdline\n");
        fclose(fd);
        return -1;
    }
    (void)fclose(fd);

    size_t firstStringLen = strnlen(buffer, bufferLen - 1);
    errno_t res = strncpy_s(caName, nameLen - 1, buffer, firstStringLen);
    if (res != EOK) {
        tloge("copy caName failed\n");
        return -1;
    }

    return bytesRead;
}

/*
 * this file "/proc/pid/cmdline" can be modified by any user,
 * so the package name we get from it is not to be trusted,
 * the CA authentication strategy does not rely much on the pkgname,
 * this is mainly to make it compatible with POHNE_PLATFORM
 */
static int TeeGetCaName(int caPid, char *caName, size_t nameLen)
{
    char path[MAX_PATH_LENGTH] = { 0 };
    char temp[CMD_MAX_SIZE] = { 0 };

    if (caName == NULL || nameLen == 0) {
        tloge("input :caName invalid\n");
        return -1;
    }

    int ret = snprintf_s(path, sizeof(path), sizeof(path) - 1, "/proc/%d/cmdline", caPid);
    if (ret == -1) {
        tloge("tee get ca name snprintf_s err\n");
        return ret;
    }

    int bytesRead = ReadCmdLine(path, temp, CMD_MAX_SIZE, caName, nameLen);

    return bytesRead;
}

int TeeGetPkgName(int caPid, char *path, size_t pathLen)
{
    if (path == NULL || pathLen > MAX_PATH_LENGTH) {
        tloge("path is null or path len overflow\n");
        return -1;
    }

    if (TeeGetCaName(caPid, path, pathLen) < 0) {
        tloge("get ca name failed\n");
        return -1;
    }

    return 0;
}
