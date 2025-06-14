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

#include "tcu_authentication.h"
#include <unistd.h>
#include <errno.h> /* for errno */
#include <fcntl.h>
#include <sys/types.h> /* for open close */
#include <sys/ioctl.h> /* for ioctl */
#include <sys/stat.h> /* for stat */
#include <linux/limits.h>
#include "securec.h"
#include "tee_log.h"
#include "tc_ns_client.h"
#include "tee_client_type.h"
#include "tee_file.h"
#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG            "tcu_authentication"
#define HASH_FILE_MAX_SIZE (16 * 1024)
#define ERR_SIZE           (-1)
#define XML_HEADER         4
#define MAX_HASHFILE_PATHLEN 256

static const char *g_vendorCaHashFileList[] = {
    "/vendor/etc/native_packages.xml",
    "/vendor/root/res/native_packages.xml",
    "/vendor/etc/passthrough/teeos/source/native_packages.xml",
};

static const char *g_systemCaHashFileList[] = {
    "/system/etc/native_packages.xml",
};

static const char *g_wholeCaHashFileList[] = {
    "/vendor/etc/native_packages.xml",
    "/system/etc/native_packages.xml",
    "/vendor/root/res/native_packages.xml",
    "/vendor/etc/passthrough/teeos/source/native_packages.xml",
};

static const char **GetCaHashFileList(uint8_t *num, uint8_t hash_type)
{
    if (num == NULL) {
        tloge("input parameter error\n");
        return NULL;
    }

    if (hash_type == HASH_TYPE_SYSTEM) {
        *num = sizeof(g_systemCaHashFileList) / sizeof(intptr_t);
        return g_systemCaHashFileList;
    } else if (hash_type == HASH_TYPE_VENDOR) {
        *num = sizeof(g_vendorCaHashFileList) / sizeof(intptr_t);
        return g_vendorCaHashFileList;
    } else {
        *num = sizeof(g_wholeCaHashFileList) / sizeof(intptr_t);
        return g_wholeCaHashFileList;
    }
}

static int IsNotValidFname(const char *path)
{
    if (path == NULL) {
        tloge("filename is invalid ...\n");
        return 1;
    }

    /* filter the .. dir in the pname: */
    if (strstr(path, "..") != NULL) {
        tloge("filename should not include .. dir\n");
        return 1;
    }

    return 0;
}

static int GetFileSize(const char *path, int *realSize)
{
    FILE *fp = NULL;
    int ret;
    int fileSize                = -1;
    int xmlHeader               = 0;
    char realPath[PATH_MAX + 1] = { 0 };

    bool paramInvlid = ((path == NULL) || (IsNotValidFname(path) != 0) || (strlen(path) > PATH_MAX) ||
                        (realpath(path, realPath) == NULL));
    if (paramInvlid) {
        return fileSize;
    }

    fp = fopen(realPath, "r");
    if (fp == NULL) {
        return fileSize;
    }

    ret = fseek(fp, 0L, SEEK_END);
    if (ret < 0) {
        fclose(fp);
        fp = NULL;
        return fileSize;
    }

    fileSize = (int)ftell(fp);

    ret = fseek(fp, 0L, SEEK_SET);
    if (ret < 0 || fileSize < XML_HEADER) {
        fclose(fp);
        fp = NULL;
        return ERR_SIZE;
    }
    int len = (int)fread(&xmlHeader, 1, sizeof(int), fp);
    if (len != sizeof(int) || xmlHeader < fileSize) {
        tloge("size read is invalid\n");
        fclose(fp);
        fp = NULL;
        return ERR_SIZE;
    }

    (void)fclose(fp);
    fp = NULL;
    *realSize = fileSize;
    return xmlHeader;
}

static int GetFileInfo(int bufLen, uint8_t *buffer, const char *path)
{
    FILE *fp = NULL;
    int fileSize;
    char realPath[PATH_MAX + 1] = { 0 };

    bool paramInvlid = ((buffer == NULL) || (path == NULL) || (IsNotValidFname(path) != 0) ||
                        (strlen(path) > PATH_MAX) || (realpath(path, realPath) == NULL) ||
                        (bufLen == 0));
    if (paramInvlid) {
        return -1;
    }

    fp = fopen(realPath, "rb");
    if (fp == NULL) {
        tloge("open file failed\n");
        return -1;
    }

    fileSize = (int)fread(buffer, sizeof(char), (unsigned int)bufLen, fp);
    if (fileSize != bufLen) {
        tloge("read file read number:%" PUBLIC "d\n", fileSize);
        fclose(fp);
        fp = NULL;
        return -1;
    }

    (void)fclose(fp);
    fp = NULL;
    return 0;
}

static uint8_t *InitTempBuf(int bufLen)
{
    errno_t ret;
    uint8_t *buffer = NULL;

    bool variablesCheck = ((bufLen <= 0) || (bufLen > HASH_FILE_MAX_SIZE));
    if (variablesCheck) {
        tloge("wrong buflen\n");
        return buffer;
    }

    buffer = (uint8_t *)malloc((unsigned int)bufLen);
    if (buffer == NULL) {
        tloge("malloc failed!\n");
        return buffer;
    }

    ret = memset_s(buffer, (unsigned int)bufLen, 0, (unsigned int)bufLen);
    if (ret != EOK) {
        tloge("memset failed!\n");
        free(buffer);
        buffer = NULL;
        return buffer;
    }

    return buffer;
}

static uint8_t *ReadXmlFile(const char *xmlFile)
{
    int ret;
    int bufLen;
    uint8_t *buffer = NULL;
    int realSize = 0;

    bufLen = GetFileSize(xmlFile, &realSize);
    buffer = InitTempBuf(bufLen);
    if (buffer == NULL) {
        tloge("init temp buffer failed\n");
        return buffer;
    }

    ret = GetFileInfo(realSize, buffer, xmlFile);
    if (ret != 0) {
        tloge("get xml file info failed\n");
        free(buffer);
        buffer = NULL;
        return buffer;
    }

    return buffer;
}

static int TeeSetNativeCaHash(const char *xmlFlie)
{
    int ret;
    int fd          = -1;
    uint8_t *buffer = NULL;

    buffer = ReadXmlFile(xmlFlie);
    if (buffer == NULL) {
        tloge("read xml file failed\n");
        return fd;
    }

    fd = tee_open(TC_PRIVATE_DEV_NAME, O_RDWR, 0);
    if (fd < 0) {
        tloge("Failed to open dev node: %" PUBLIC "d\n", errno);
        free(buffer);
        buffer = NULL;
        return -1;
    }
    ret = ioctl(fd, (int)(TC_NS_CLIENT_IOCTL_SET_NATIVE_IDENTITY), buffer);
    if (ret != 0) {
        tloge("ioctl fail %" PUBLIC "d\n", ret);
    }

    free(buffer);
    buffer = NULL;
    tee_close(&fd);
    return ret;
}

static bool IsFileExist(const char *name)
{
    struct stat statbuf;

    if (name == NULL) {
        return false;
    }
    if (stat(name, &statbuf) != 0) {
        if (errno == ENOENT) { /* file not exist */
            tlogi("file not exist: %" PUBLIC "s\n", name);
            return false;
        }
        return true;
    }

    return true;
}

int TcuAuthentication(uint8_t hash_type)
{
    uint8_t listLen;
    const char **hashFileList = GetCaHashFileList(&listLen, hash_type);
    if (hashFileList == NULL) {
        tloge("get hashFileList failed\n");
        return -1;
    }
    if (listLen == 0) {
        tloge("list num is 0, please set hashfile\n");
        return -1;
    }
    static int gHashXmlSetted;
    uint8_t count = 0;
    if (gHashXmlSetted == 0) {
        for (uint8_t index = 0; index < listLen; index++) {
            if (hashFileList[index] == NULL) {
                tloge("get hashFile failed, index is %" PUBLIC "d\n", index);
                continue;
            }
            if (!IsFileExist(hashFileList[index])) {
                continue;
            }
            int setRet = TeeSetNativeCaHash(hashFileList[index]);
            if (setRet != 0) {
                tloge("hashfile read failed, index is %" PUBLIC "d\n", index);
                continue;
            }
            count++;
        }
    }

    if (count == listLen) {
        gHashXmlSetted = 1;
        return 0;
    }

    return -1;
}
