/*
 * Copyright (C) 2023 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include "tee_load_dynamic.h"
#include <sys/stat.h>  /* for stat */
#include <dirent.h>
#include <limits.h>

#include "securec.h"
#include "tc_ns_client.h"
#include "tee_log.h"
#include "secfile_load_agent.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "teecd_load_dynamic"

#if defined(DYNAMIC_DRV_DIR) || defined(DYNAMIC_CRYPTO_DRV_DIR) || defined(DYNAMIC_SRV_DIR)
#define MAX_FILE_NAME_LEN 128

static DIR *OpenDynamicDir(const char *dynDir)
{
    DIR *dir = opendir(dynDir);
    if (dir == NULL) {
        tlogw("open drv dir: %" PUBLIC "s failed\n", dynDir);
    }

    return dir;
}

static int32_t endsWith(const char *str, const char *suffix)
{
    size_t strLen = strnlen(str, MAX_FILE_NAME_LEN);
    size_t suffixLen = strnlen(suffix, MAX_FILE_NAME_LEN);
    if (suffixLen > strLen || strLen == 0 || strLen >= MAX_FILE_NAME_LEN || suffixLen == 0) {
        return -1;
    }

    const char *ptr = str + (strLen - suffixLen);
    if (strcmp(ptr, suffix) == 0) {
        return 0;
    }

    return -1;
}

static int32_t LoadOneFile(const char *dynDir, const struct dirent *dirFile, int32_t fd, uint32_t loadType)
{
    char name[MAX_FILE_NAME_LEN];
    FILE *fp = NULL;
    int32_t ret = -1;

    if (endsWith(dirFile->d_name, ".sec") != 0) {
        tloge("file name does not end with .sec\n");
        goto END;
    }

    if (memset_s(name, sizeof(name), 0, sizeof(name)) != 0) {
        tloge("mem set failed, name: %" PUBLIC "s, size: %" PUBLIC "u\n", name, (uint32_t)sizeof(name));
        goto END;
    }
    if (strcat_s(name, MAX_FILE_NAME_LEN, dynDir) != 0) {
        tloge("dir name too long: %" PUBLIC "s\n", dynDir);
        goto END;
    }
    if (strcat_s(name, MAX_FILE_NAME_LEN, dirFile->d_name) != 0) {
        tloge("drv name too long: %" PUBLIC "s\n", dirFile->d_name);
        goto END;
    }

    fp = fopen(name, "r");
    if (fp == NULL) {
        tloge("open drv failed: %" PUBLIC "s\n", name);
        goto END;
    }

    ret = LoadSecFile(fd, fp, loadType, NULL);
    if (ret != 0) {
        tloge("load dynamic failed: %" PUBLIC "s\n", name);
    }

END:
    if (fp != NULL) {
        (void)fclose(fp);
    }

    return ret;
}

static int32_t LoadOneDynamicDir(int32_t fd, const char *dynDir, uint32_t loadType)
{
    int32_t ret = -1;
    struct dirent *dirFile = NULL;

    DIR *dir = OpenDynamicDir(dynDir);
    if (dir == NULL) {
        tlogi("dynamic dir not exist dyndir=%" PUBLIC"s\n", dynDir);
        return ret;
    }
    while ((dirFile = readdir(dir)) != NULL) {
        if (dirFile->d_type != DT_REG) {
            tlogd("no need to load\n");
            continue;
        }
        ret = LoadOneFile(dynDir, dirFile, fd, loadType);
        if (ret != 0) {
            tlogd("load dynamic failed\n");
            continue;
        }
    }

    (void)closedir(dir);
    return ret;
}

void LoadDynamicCryptoDir(void)
{
#ifdef DYNAMIC_CRYPTO_DRV_DIR
    int32_t fd = GetSecLoadAgentFd();
    (void)LoadOneDynamicDir(fd, DYNAMIC_CRYPTO_DRV_DIR, LOAD_DYNAMIC_DRV);
#endif
}

static int32_t CheckPath(const char *drvPath, uint32_t drvPathLen, char *trustDrvPath)
{
    char trustDrvRootPath[PATH_MAX] = {0};
    size_t optLen = strnlen(drvPath, MAX_FILE_NAME_LEN);
    if (optLen == 0 || optLen >= MAX_FILE_NAME_LEN || drvPathLen != optLen) {
        tloge("drv path is invalid\n");
        return -1;
    }

    size_t rootLen = strnlen(DYNAMIC_DRV_DIR, MAX_FILE_NAME_LEN);
    if (rootLen == 0 || rootLen >= MAX_FILE_NAME_LEN) {
        tloge("drv root path is invalid\n");
        return -1;
    }

    if (realpath(drvPath, trustDrvPath) == NULL) {
        tloge("check realpath failed\n");
        return -1;
    }

    if (realpath(DYNAMIC_DRV_DIR, trustDrvRootPath) == NULL) {
        tloge("check realpath failed\n");
        return -1;
    }

    rootLen = strnlen(trustDrvRootPath, MAX_FILE_NAME_LEN);
    if (rootLen == 0 || rootLen >= MAX_FILE_NAME_LEN) {
        tloge("drv root path is invalid\n");
        return -1;
    }

    optLen = strnlen(trustDrvPath, MAX_FILE_NAME_LEN);
    if (optLen <= rootLen || optLen >= MAX_FILE_NAME_LEN) {
        tloge("drv path is invalid\n");
        return -1;
    }

    if (strncmp(trustDrvPath, trustDrvRootPath, rootLen) != 0) {
        tloge("drv path is invalid, %" PUBLIC "s, %" PUBLIC "s\n", trustDrvPath, trustDrvRootPath);
        return -1;
    }

    return 0;
}

void LoadDynamicDrvDir(const char *drvPath, uint32_t drvPathLen)
{
#ifdef DYNAMIC_DRV_DIR
    int32_t fd = GetSecLoadAgentFd();
    if (drvPathLen == 0 || drvPath == NULL) {
#ifdef DYNAMIC_DRV_FEIMA_DIR
        if (LoadOneDynamicDir(fd, DYNAMIC_DRV_FEIMA_DIR, LOAD_DYNAMIC_DRV)) {
#endif
            LoadOneDynamicDir(fd, DYNAMIC_DRV_DIR, LOAD_DYNAMIC_DRV);
#ifdef DYNAMIC_DRV_FEIMA_DIR
        }
#endif
    } else {
        char trustDrvPath[PATH_MAX] = {0};
        if (CheckPath(drvPath, drvPathLen, trustDrvPath) != 0) {
            tloge("check path failed\n");
            return;
        }
        if (strcat_s(trustDrvPath, PATH_MAX, "/") != 0) {
            tloge("add / to trust drv path failed\n");
            return;
        }

        (void)LoadOneDynamicDir(fd, drvPath, LOAD_DYNAMIC_DRV);
    }
#endif
}

void LoadDynamicSrvDir(void)
{
#ifdef DYNAMIC_SRV_DIR
    int32_t fd = GetSecLoadAgentFd();
#ifdef DYNAMIC_SRV_FEIMA_DIR
    if (LoadOneDynamicDir(fd, DYNAMIC_SRV_FEIMA_DIR, LOAD_SERVICE)) {
#endif
        (void)LoadOneDynamicDir(fd, DYNAMIC_SRV_DIR, LOAD_SERVICE);
#ifdef DYNAMIC_SRV_FEIMA_DIR
    }
#endif
#endif
}
#endif
