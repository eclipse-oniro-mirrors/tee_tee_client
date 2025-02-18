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

#include "load_sec_file.h"
#include <sys/ioctl.h> /* for ioctl */
#include <sys/prctl.h>
#include "securec.h"
#include "tc_ns_client.h"
#include "tee_log.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "load_secfile"
#define MAX_BUFFER_LEN (8 * 1024 * 1024)
#define H_OFFSET                  32

static int GetImgLen(FILE *fp, long *totalLlen)
{
    int ret;

    ret = fseek(fp, 0, SEEK_END);
    if (ret != 0) {
        tloge("fseek end error\n");
        return -1;
    }
    *totalLlen = ftell(fp);
    if (*totalLlen <= 0 || *totalLlen > MAX_BUFFER_LEN) {
        tloge("file is not exist or size is too large, filesize = %" PUBLIC "ld\n", *totalLlen);
        return -1;
    }
    ret = fseek(fp, 0, SEEK_SET);
    if (ret != 0) {
        tloge("fseek head error\n");
        return -1;
    }
    return ret;
}

/* input param uuid may be NULL, so don need to check if uuid is NULL */
int32_t LoadSecFile(int tzFd, FILE *fp, enum SecFileType fileType, const TEEC_UUID *uuid)
{
    int32_t ret;
    char *fileBuffer                   = NULL;
    struct SecLoadIoctlStruct ioctlArg = {{ 0 }, { 0 }, { NULL } };

    if (tzFd < 0 || fp == NULL) {
        tloge("param erro!\n");
        return -1;
    }

    do {
        long totalLen = 0;
        ret           = GetImgLen(fp, &totalLen);
        if (ret != 0) {
            break;
        }

        if (totalLen <= 0 || totalLen > MAX_BUFFER_LEN) {
            ret = -1;
            tloge("totalLen is invalid\n");
            break;
        }

        /* alloc a less than 8M heap memory, it needn't slice. */
        fileBuffer = malloc(totalLen);
        if (fileBuffer == NULL) {
            tloge("alloc TA file buffer(size=%" PUBLIC "ld) failed\n", totalLen);
            ret = -1;
            break;
        }

        /* read total ta file to file buffer */
        long fileSize = (long)fread(fileBuffer, 1, totalLen, fp);
        if (fileSize != totalLen) {
            tloge("read ta file failed, read size/total size=%" PUBLIC "ld/%" PUBLIC "ld\n", fileSize, totalLen);
            ret = -1;
            break;
        }

        ioctlArg.secFileInfo.fileType = fileType;
        ioctlArg.secFileInfo.fileSize = (uint32_t)totalLen;
        ioctlArg.memref.file_addr = (uint32_t)(uintptr_t)fileBuffer;
        ioctlArg.memref.file_h_addr = (uint32_t)(((uint64_t)(uintptr_t)fileBuffer) >> H_OFFSET);
        if (uuid != NULL && memcpy_s((void *)(&ioctlArg.uuid), sizeof(ioctlArg.uuid), uuid, sizeof(*uuid)) != EOK) {
            tloge("memcpy uuid fail\n");
            break;
        }

        ret = ioctl(tzFd, (int)TC_NS_CLIENT_IOCTL_LOAD_APP_REQ, &ioctlArg);
        if (ret != 0) {
            tloge("ioctl to load sec file failed, ret = 0x%" PUBLIC "x\n", ret);
        }
    } while (false);

    if (fileBuffer != NULL) {
        free(fileBuffer);
    }
    return ret;
}

