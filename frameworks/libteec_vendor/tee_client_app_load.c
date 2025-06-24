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

#include "tee_client_app_load.h"
#include <fcntl.h>
#include <limits.h>
#include <securec.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>  /* for mmap */
#include <sys/ioctl.h> /* for ioctl */
#include <sys/stat.h>
#include <sys/types.h> /* for open close */
#include "load_sec_file.h"
#include "tc_ns_client.h"
#include "tee_client_inner.h"
#include "tee_log.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "teec_app_load"

#define MAX_PATH_LEN 256

static int32_t TEEC_ReadApp(const TaFileInfo *taFile, const char *loadFile, bool defaultPath,
                            TC_NS_ClientContext *cliContext);

int32_t TEEC_GetApp(const TaFileInfo *taFile, const TEEC_UUID *srvUuid, TC_NS_ClientContext *cliContext)
{
    int32_t ret;

    if ((taFile == NULL) || (srvUuid == NULL) || (cliContext == NULL)) {
        tloge("param is null\n");
        return -1;
    }

    /* get file name and file patch */
    bool condition = (taFile->taPath != NULL) && (strlen((const char *)taFile->taPath) < MAX_PATH_LEN) &&
                     strstr((const char *)taFile->taPath, ".sec");
    if (condition) {
        ret = TEEC_ReadApp(taFile, (const char *)taFile->taPath, false, cliContext);
        if (ret < 0) {
            tlogi("ta path is not NULL, ta file will be readed by driver\n");
            ret = 0;
        }
    } else {
        char fileName[MAX_FILE_NAME_LEN]                                        = { 0 };
        char tempName[MAX_FILE_PATH_LEN + MAX_FILE_NAME_LEN + MAX_FILE_EXT_LEN] = { 0 };
        const char *filePath = TEE_FEIMA_DEFAULT_PATH;
        ret = snprintf_s(fileName, sizeof(fileName), sizeof(fileName) - 1,
                         "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x", srvUuid->timeLow, srvUuid->timeMid,
                         srvUuid->timeHiAndVersion, srvUuid->clockSeqAndNode[0], srvUuid->clockSeqAndNode[1],
                         srvUuid->clockSeqAndNode[2], srvUuid->clockSeqAndNode[3], srvUuid->clockSeqAndNode[4],
                         srvUuid->clockSeqAndNode[5], srvUuid->clockSeqAndNode[6], srvUuid->clockSeqAndNode[7]);
        if (ret < 0) {
            tloge("get file name err\n");
            return -1;
        }

        size_t filePathLen = strnlen(filePath, MAX_FILE_PATH_LEN);
        filePathLen        = filePathLen + strnlen(fileName, MAX_FILE_NAME_LEN) + MAX_FILE_EXT_LEN;
        if (snprintf_s(tempName, sizeof(tempName), filePathLen, "%s/%s.sec", filePath, fileName) < 0) {
            tloge("file path too long\n");
            return -1;
        }

        if (TEEC_ReadApp(taFile, (const char *)tempName, true, cliContext) != 0) {
            tlogi("teec load app from feima path failed, try to load from old path\n");
            memset_s(tempName, sizeof(tempName), 0, sizeof(tempName));
            if (snprintf_s(tempName, sizeof(tempName), filePathLen, "%s/%s.sec", TEE_DEFAULT_PATH, fileName) < 0) {
                return -1;
            }

            if (TEEC_ReadApp(taFile, (const char *)tempName, true, cliContext) < 0) {
                tloge("teec load app erro\n");
                return -1;
            }
            /* TA file is not in the default path and feima default path, maybe it's a build-in TA */
            ret = 0;
        }
    }

    return ret;
}

static int32_t GetTaVersion(FILE *fp, uint32_t *taHeadLen, uint32_t *version,
                            uint32_t *contextLen, uint32_t *totalImgLen)
{
    int32_t ret;
    TaImageHdrV3 imgHdr = { { 0 }, 0, 0 };

    if (fp == NULL) {
        tloge("invalid fp\n");
        return -1;
    }

    /* get magic-num & version-num */
    ret = (int32_t)fread(&imgHdr, sizeof(imgHdr), 1, fp);
    if (ret != 1) {
        tloge("read file failed, ret=%" PUBLIC "d, error=%" PUBLIC "d\n", ret, ferror(fp));
        return -1;
    }

    bool condition = (imgHdr.imgIdentity.magicNum1 == TA_HEAD_MAGIC1) &&
                     (imgHdr.imgIdentity.magicNum2 == TA_HEAD_MAGIC2 ||
                     imgHdr.imgIdentity.magicNum2 == TA_OH_HEAD_MAGIC2) &&
                     (imgHdr.imgIdentity.versionNum > 1);
    if (condition) {
        tlogd("new verison ta\n");
        *taHeadLen = sizeof(TeecTaHead);
        *version   = imgHdr.imgIdentity.versionNum;
        if (*version >= CIPHER_LAYER_VERSION) {
            *contextLen  = imgHdr.contextLen;
            *totalImgLen = *contextLen + sizeof(imgHdr);
        } else {
            ret = fseek(fp, sizeof(imgHdr.imgIdentity), SEEK_SET);
            if (ret != 0) {
                tloge("fseek error\n");
                return -1;
            }
        }
    } else {
        /* read the oldverison head again */
        tlogd("old verison ta\n");
        *taHeadLen = sizeof(TeecImageHead);
        ret       = fseek(fp, 0, SEEK_SET);
        if (ret != 0) {
            tloge("fseek error\n");
            return -1;
        }
    }
    return 0;
}

static int32_t TEEC_GetImageLenth(FILE *fp, uint32_t *imgLen)
{
    int32_t ret;
    TeecImageHead imageHead = { 0 };
    uint32_t totalImgLen;
    uint32_t taHeadLen = 0;
    uint32_t readSize;
    uint32_t version    = 0;
    uint32_t contextLen = 0;

    /* decide the TA verison */
    ret = GetTaVersion(fp, &taHeadLen, &version, &contextLen, &totalImgLen);
    if (ret != 0) {
        tloge("get Ta version failed\n");
        return ret;
    }

    if (version >= CIPHER_LAYER_VERSION) {
        goto CHECK_LENTH;
    }

    /* get image head */
    readSize = (uint32_t)fread(&imageHead, sizeof(TeecImageHead), 1, fp);
    if (readSize != 1) {
        tloge("read file failed, err=%" PUBLIC "u\n", readSize);
        return -1;
    }
    contextLen  = imageHead.contextLen;
    totalImgLen = contextLen + taHeadLen;

CHECK_LENTH:
    /* for no overflow */
    if ((contextLen > MAX_IMAGE_LEN) || (totalImgLen > MAX_IMAGE_LEN)) {
        tloge("check img size failed\n");
        return -1;
    }

    ret = fseek(fp, 0, SEEK_SET);
    if (ret != 0) {
        tloge("fseek error\n");
        return -1;
    }

    *imgLen = totalImgLen;
    return 0;
}

static int32_t TEEC_DoReadApp(FILE *fp, TC_NS_ClientContext *cliContext)
{
    uint32_t totalImgLen = 0;

    /* get magic-num & version-num */
    int32_t ret = TEEC_GetImageLenth(fp, &totalImgLen);
    if (ret) {
        tloge("get image lenth fail\n");
        return -1;
    }

    if (totalImgLen == 0 || totalImgLen > MAX_IMAGE_LEN) {
        tloge("image lenth invalid\n");
        return -1;
    }

    /* alloc a less than 8M heap memory, it needn't slice. */
    char *fileBuffer = malloc(totalImgLen);
    if (fileBuffer == NULL) {
        tloge("alloc TA file buffer(size=%" PUBLIC "u) failed\n", totalImgLen);
        return -1;
    }

    /* read total ta file to file buffer */
    uint32_t readSize = (uint32_t)fread(fileBuffer, 1, totalImgLen, fp);
    if (readSize != totalImgLen) {
        tloge("read ta file failed, read size/total size=%" PUBLIC "u/%" PUBLIC "u\n", readSize, totalImgLen);
        free(fileBuffer);
        return -1;
    }
    cliContext->file_size   = totalImgLen;
    cliContext->file_buffer = fileBuffer;
    return 0;
}

static int32_t TEEC_ReadApp(const TaFileInfo *taFile, const char *loadFile, bool defaultPath,
                            TC_NS_ClientContext *cliContext)
{
    int32_t ret                     = 0;
    int32_t retBuildInTa            = 1;
    FILE *fp                        = NULL;
    FILE *fpTmp                     = NULL;
    char realLoadFile[PATH_MAX + 1] = { 0 };

    if (taFile->taFp != NULL) {
        fp = taFile->taFp;
        tlogd("libteec_vendor-read_app: get fp from ta fp\n");
        goto READ_APP;
    }

    if (realpath(loadFile, realLoadFile) == NULL) {
        if (!defaultPath) {
            tloge("get file realpath error%" PUBLIC "d\n", errno);
            return -1;
        }

        /* maybe it's a built-in TA */
        tlogd("maybe it's a built-in TA or file is not in default path\n");
        return retBuildInTa;
    }

    /* open image file */
    fpTmp = fopen(realLoadFile, "r");
    if (fpTmp == NULL) {
        tloge("open file error%" PUBLIC "d\n", errno);
        return -1;
    }
    fp = fpTmp;

READ_APP:
    ret = TEEC_DoReadApp(fp, cliContext);
    if (ret != 0) {
        tloge("do read app fail\n");
    }

    if (fpTmp != NULL) {
        fclose(fpTmp);
    }

    return ret;
}

int32_t TEEC_LoadSecfile(const char *filePath, int tzFd, FILE *fp)
{
    int ret;
    FILE *fpUsable              = NULL;
    bool checkValue             = (tzFd < 0 || filePath == NULL);
    FILE *fpCur                 = NULL;

    if (checkValue) {
        tloge("Param err!\n");
        return -1;
    }
    if (fp == NULL) {
        char realPath[PATH_MAX + 1] = { 0 };
        if (realpath(filePath, realPath) != NULL) {
            fpCur = fopen(realPath, "r");
        }
        if (fpCur == NULL) {
            tloge("realpath open file erro%" PUBLIC "d, path=%" PUBLIC "s\n", errno, filePath);
            return -1;
        }
        fpUsable = fpCur;
    } else {
        fpUsable = fp;
    }
    ret = LoadSecFile(tzFd, fpUsable, LOAD_LIB, NULL);
    if (fpCur != NULL) {
        fclose(fpCur);
    }
    return ret;
}
