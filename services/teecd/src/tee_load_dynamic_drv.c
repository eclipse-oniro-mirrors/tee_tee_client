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

#include "tee_load_dynamic_drv.h"
#include <dirent.h>
#include <limits.h>
#include <securec.h>
#include <sys/stat.h>
#include "secfile_load_agent.h"
#include "tc_ns_client.h"
#include "tee_log.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "teecd_load_dynamic_elf"

#define MAX_FILE_NAME_LEN 128

static int32_t LoadOneFile(const char *dynDir, const struct dirent *dirFile, int32_t fd, uint32_t loadType)
{
    char name[MAX_FILE_NAME_LEN];
    FILE *fp = NULL;
    int32_t ret = -1;

    if (strcmp(dirFile->d_name, ".") == 0 || strcmp(dirFile->d_name, "..") == 0) {
        tloge("no need to load\n");
        goto END;
    }

    if (strstr(dirFile->d_name, ".sec") == NULL) {
        tloge("only support sec file\n");
        goto END;
    }

    if (memset_s(name, sizeof(name), 0, sizeof(name)) != 0) {
        tloge("mem set failed, name: %s, size: %u\n", name, (uint32_t)sizeof(name));
        goto END;
    }
    if (strcat_s(name, MAX_FILE_NAME_LEN, dynDir) != 0) {
        tloge("dir name too long: %s\n", dynDir);
        goto END;
    }
    if (strcat_s(name, MAX_FILE_NAME_LEN, dirFile->d_name) != 0) {
        tloge("drv name too long: %s\n", dirFile->d_name);
        goto END;
    }

    char realLoadFile[PATH_MAX + 1] = { 0 };
    if (realpath(name, realLoadFile) == NULL) {
        tloge("real path failed err=%d\n", errno);
        goto END;
    }

    fp = fopen(realLoadFile, "r");
    if (fp == NULL) {
        tloge("open drv failed: %s\n", realLoadFile);
        goto END;
    }

    ret = LoadSecFile(fd, fp, loadType, NULL);
    if (ret != 0) {
        tloge("load dynamic drv or srv failed: %s\n", realLoadFile);
    }

END:
    if (fp != NULL) {
        (void)fclose(fp);
    }

    return ret;
}

static void LoadOneDynamicDir(int32_t fd, const char *dynDir, uint32_t loadType)
{
    int32_t ret;
    struct dirent *dirFile = NULL;

    DIR *dir = opendir(dynDir);
    if (dir == NULL) {
        tlogi("tee dynamic dir not exist\n");
        return;
    }
    while ((dirFile = readdir(dir)) != NULL) {
        ret = LoadOneFile(dynDir, dirFile, fd, loadType);
        if (ret != 0) {
            tloge("load dynamic failed\n");
            continue;
        }
    }
    (void)closedir(dir);
}

void LoadDynamicDir()
{
    int32_t fd = GetSecLoadAgentFd();

    LoadOneDynamicDir(fd, DYNAMIC_DRV_DIR, LOAD_DYNAMIC_DRV);
    LoadOneDynamicDir(fd, DYNAMIC_SRV_DIR, LOAD_SERVICE);
}