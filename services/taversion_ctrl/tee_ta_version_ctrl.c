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

#include <errno.h> /* for errno */
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h> /* for open close */
#include <sys/ioctl.h> /* for ioctl */
#include <sys/stat.h> /* for stat */
#include <linux/limits.h>
#include "securec.h"
#include "tc_ns_client.h"
#include "tee_log.h"
#include "tee_ta_version_ctrl.h"
#include "tee_file.h"

#define HASH_FILE_MAX_SIZE (70 * 1024)

static const char *g_taVersionCtrlFileList[] = {
    "/vendor/etc/ta_ctrl.ctrl",
    "/system/etc/ta_ctrl.ctrl",
};

static uint32_t GetFileInfo(const char *fileName, uint8_t **buffer)
{
    uint32_t file_size = 0;
    char realPath[PATH_MAX + 1] = { 0 };
    struct stat statbuf;
    if (fileName == NULL || strnlen(fileName, PATH_MAX) == PATH_MAX) {
        tloge("ta vertion control file name is invalid.");
        return 0;
    }
    if (stat(fileName, &statbuf) != 0) {
        tloge("ta vertion control file [%" PUBLIC "s] stat failed, errno is %" PUBLIC "d\n", fileName, errno);
        return 0;
    }
    file_size = (uint32_t)statbuf.st_size;
    if (file_size == 0 || file_size > HASH_FILE_MAX_SIZE) {
        tloge("ta vertion control file size is invalid, size is %" PUBLIC "u\n", file_size);
        return 0;
    }

    if (realpath(fileName, realPath) == NULL) {
        tloge("realPath open file errno = %" PUBLIC "d, fileName = %" PUBLIC "s\n", errno, fileName);
        return 0;
    }
    FILE *fp = fopen(realPath, "r");
    if (fp == NULL) {
        tloge("fopen file failed, file name is %" PUBLIC "s\n", realPath);
        return file_size;
    }

    *buffer = (uint8_t *)malloc(sizeof(uint8_t) * file_size);
    if (*buffer == NULL) {
        tloge("malloc failed, file name is %" PUBLIC "s, file size is %" PUBLIC "u\n", realPath, file_size);
        fclose(fp);
        return 0;
    }

    uint64_t ret = fread(*buffer, file_size, 1, fp);
    if (ret == 0) {
        free(*buffer);
        *buffer = NULL;
        fclose(fp);
        tloge("fread fail\n");
        return 0;
    }
    (void)fclose(fp);
    return file_size;
}

static int TeeSetTaVertionList(const char *fileName)
{
    uint8_t *buffer = NULL;
    uint32_t file_size = GetFileInfo(fileName, &buffer);
    if (file_size == 0) {
        tloge("get file info failed, file name is %" PUBLIC "s\n", fileName);
        return -1;
    }

    int fd = -1;
    fd = tee_open(TC_PRIVATE_DEV_NAME, O_RDWR, 0);
    if (fd < 0) {
        tloge("Failed to open dev node: %" PUBLIC "d\n", errno);
        free(buffer);
        buffer = NULL;
        return -1;
    }
    struct TaCtrlInfo ta_ctrl = {};
    ta_ctrl.buffer = buffer;
    ta_ctrl.size = file_size;
    int ret = ioctl(fd, (int)(TC_NS_CLIENT_IOCTL_SET_TA_CONTROL_VERSION), &ta_ctrl);
    if (ret != 0) {
        tloge("ioctl fail %" PUBLIC "d, errno is %" PUBLIC "d\n", ret, errno);
    }
    free(buffer);
    buffer = NULL;
    tee_close(&fd);
    return 0;
}

bool SetTaVersionCtrl(uint8_t ctrl_type)
{
    if (ctrl_type >= sizeof(g_taVersionCtrlFileList) / sizeof(g_taVersionCtrlFileList[0])) {
        tloge("ctrl_type is invalid, ctrl_type is %" PUBLIC "u\n", ctrl_type);
        return false;
    }
    const char *ta_ctrl_filename = g_taVersionCtrlFileList[ctrl_type];
    int ret = TeeSetTaVertionList(ta_ctrl_filename);
    if (ret != 0) {
        tloge("ta version file read failed\n");
        return false;
    }
    return true;
}

void InitTaVersionCtrl(uint8_t ctrl_type)
{
    static bool sendCtrlFlag = false;
    if (sendCtrlFlag) {
        return;
    }
    if (SetTaVersionCtrl(ctrl_type)) {
        sendCtrlFlag = true;
    }
}
