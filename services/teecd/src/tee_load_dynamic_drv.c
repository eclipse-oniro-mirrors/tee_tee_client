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
#define LOG_TAG "teecd_load_dynamic_drv"

#define MAX_FILE_NAME_LEN 128

static DIR *OpenDynamicDir(void)
{
    DIR *dir = opendir(DYNAMIC_DRV_DIR);
    if (dir == NULL) {
        tloge("open drv dir: %s failed\n", DYNAMIC_DRV_DIR);
    }

    return dir;
}

static int32_t LoadOneDrv(const struct dirent *dirFile, int32_t fd)
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
    if (strcat_s(name, MAX_FILE_NAME_LEN, DYNAMIC_DRV_DIR) != 0) {
        tloge("dir name too long: %s\n", DYNAMIC_DRV_DIR);
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

    ret = LoadSecFile(fd, fp, LOAD_DYNAMIC_DRV, NULL);
    if (ret != 0) {
        tloge("load drnamic_drv failed: %s\n", realLoadFile);
    }

END:
    if (fp != NULL) {
        (void)fclose(fp);
    }

    return ret;
}

void LoadDynamicDir(void)
{
    struct dirent *dirFile = NULL;
    int fd = GetSecLoadAgentFd();

    DIR *dir = OpenDynamicDir();
    if (dir == NULL) {
        tloge("dynamic_drv dir not exist\n");
        return;
    }

    while ((dirFile = readdir(dir)) != NULL) {
        int32_t ret = LoadOneDrv(dirFile, fd);
        if (ret != 0) {
            tloge("load dynamic drv failed\n");
            continue;
        }
    }

    (void)closedir(dir);
}
