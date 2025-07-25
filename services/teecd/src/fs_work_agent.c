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

#include "fs_work_agent.h"
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <mntent.h>
#include <securec.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <time.h>
#include "tc_ns_client.h"
#include "tee_agent.h"
#include "tee_log.h"
#include "tee_file.h"
#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG       "teecd_agent"
#define USER_PATH_LEN 10

#define USEC_PER_SEC    1000000ULL
#define USEC_PER_MSEC   1000ULL
#define NSEC_PER_USEC   1000ULL
#define FSCMD_TIMEOUT_US (1 * USEC_PER_SEC)

static int32_t CopyFile(const char *fromPath, const char *toPath);

/* record the current g_userId and g_storageId */
static uint32_t g_userId;
static uint32_t g_storageId;
static void SetCurrentUserId(uint32_t id)
{
    g_userId = id;
}
static uint32_t GetCurrentUserId(void)
{
    return g_userId;
}

static void SetCurrentStorageId(uint32_t id)
{
    g_storageId = id;
}
static uint32_t GetCurrentStorageId(void)
{
    return g_storageId;
}

/* open file list head */
static struct OpenedFile *g_firstFile = NULL;

/* add to tail */
static int32_t AddOpenFile(FILE *pFile)
{
    struct OpenedFile *newFile = malloc(sizeof(struct OpenedFile));
    if (newFile == NULL) {
        tloge("malloc OpenedFile failed\n");
        return -1;
    }
    newFile->file = pFile;

    if (g_firstFile == NULL) {
        g_firstFile   = newFile;
        newFile->next = newFile;
        newFile->prev = newFile;
    } else {
        if (g_firstFile->prev == NULL) {
            tloge("the tail is null\n");
            free(newFile);
            return -1;
        }
        g_firstFile->prev->next = newFile;
        newFile->prev           = g_firstFile->prev;
        newFile->next           = g_firstFile;
        g_firstFile->prev       = newFile;
    }
    return 0;
}

static void DelOpenFile(struct OpenedFile *file)
{
    struct OpenedFile *next = NULL;

    if (file == NULL) {
        return;
    }
    next = file->next;

    if (file == next) { /* only 1 node */
        g_firstFile = NULL;
    } else {
        if (file->next == NULL || file->prev == NULL) {
            tloge("the next or the prev is null\n");
            return;
        }
        if (file == g_firstFile) {
            g_firstFile = file->next;
        }
        next->prev       = file->prev;
        file->prev->next = next;
    }
}

static int32_t FindOpenFile(int32_t fd, struct OpenedFile **file)
{
    struct OpenedFile *p = g_firstFile;
    int32_t findFlag     = 0;

    if (p == NULL) {
        return findFlag;
    }

    do {
        if (p->file != NULL) {
            if (fileno(p->file) == fd) {
                findFlag = 1;
                break;
            }
        }
        p = p->next;
    } while (p != g_firstFile && p != NULL);

    if (findFlag == 0) {
        p = NULL;
    }
    if (file != NULL) {
        *file = p;
    }
    return findFlag;
}

/*
 * path: file or dir to change own
 * is_file: 0(dir);1(file)
 */
static void ChownSecStorage(const char *path, bool is_file)
{
    if (path == NULL) {
        return;
    }
    /* create dirs with 700 mode, create files with 600 mode */
    int32_t ret;
    if (is_file) {
        ret = chmod(path, SFS_FILE_PERM);
    } else {
        ret = chmod(path, SFS_DIR_PERM);
    }
    if (ret < 0) {
        tloge("chmod failed: %" PUBLIC "d\n", errno);
    }
}

static int32_t CheckPathLen(const char *path, size_t pathLen)
{
    uint32_t i = 0;

    while (i < pathLen && path[i] != '\0') {
        i++;
    }
    if (i >= pathLen) {
        tloge("path is too long\n");
        return -1;
    }
    return 0;
}

/*
 * path:file path name.
 * e.g. sec_storage_data/app1/sub1/fileA.txt
 * then CreateDir will make dir sec_storage_data, app1 and sub1.
 */
static int32_t CreateDir(const char *path, size_t pathLen)
{
    int32_t ret;

    ret = CheckPathLen(path, pathLen);
    if (ret != 0) {
        return -1;
    }

    char *pathTemp = strdup(path);
    char *position  = pathTemp;

    if (pathTemp == NULL) {
        tloge("strdup error\n");
        return -1;
    }

    if (strncmp(pathTemp, "/", strlen("/")) == 0) {
        position++;
    } else if (strncmp(pathTemp, "./", strlen("./")) == 0) {
        position += strlen("./");
    }

    for (; *position != '\0'; ++position) {
        if (*position == '/') {
            *position = '\0';

            if (access(pathTemp, F_OK) == 0) {
                /* Temporary solution to incorrect permission on the sfs
                 * directory, avoiding factory settings restoration
                 */
                (void)chmod(pathTemp, SFS_DIR_PERM);

                *position = '/';
                continue;
            }

            if (mkdir(pathTemp, SFS_DIR_PERM) != 0) {
                tloge("mkdir fail err %" PUBLIC "d \n", errno);
                free(pathTemp);
                return -1;
            }

            *position = '/';
        }
    }

    free(pathTemp);
    return 0;
}

static int32_t CheckFileNameAndPath(const char *name, const char *path)
{
    if (name == NULL || path == NULL) {
        return -1;
    }

    if (strstr(name, FILE_NAME_INVALID_STR) != NULL) {
        tloge("Invalid file name\n");
        return -1;
    }

    return 0;
}

#ifdef CONFIG_BACKUP_PARTITION
static int32_t CheckEnvPath(const char *envPath, char *trustPath, size_t trustPathLen)
{
    struct stat st;

    if (strnlen(envPath, PATH_MAX) > trustPathLen) {
        tloge("too long envPath\n");
        return -1;
    }
    char *retPath = realpath(envPath, trustPath);
    if (retPath == NULL) {
        tloge("error envpath, errno is %" PUBLIC "d\n", errno);
        return errno;
    }

    if (stat(trustPath, &st) < 0) {
        tloge("stat failed, errno is %" PUBLIC "x\n", errno);
        return -1;
    }
    if (!S_ISDIR(st.st_mode)) {
        tloge("error path: is not a dir\n");
        return -1;
    }
    size_t pathLen = strlen(trustPath);
    if (pathLen >= trustPathLen - 1) {
        tloge("too long to add / \n");
        return -1;
    }
    trustPath[pathLen] = '/';
    trustPath[pathLen + 1] = '\0';
    return 0;
}
#endif

static int32_t GetPathStorage(char *path, size_t pathLen, const char *env)
{
    errno_t rc;
    char *defaultPath = NULL;

    if (strncmp(env, "SFS_PARTITION_TRANSIENT", strlen("SFS_PARTITION_TRANSIENT")) == 0) {
        defaultPath = USER_DATA_DIR;
    } else if (strncmp(env, "SFS_PARTITION_PERSISTENT", strlen("SFS_PARTITION_PERSISTENT")) == 0) {
        defaultPath = ROOT_DIR;
    } else {
        return -1;
    }

    rc = strncpy_s(path, pathLen, defaultPath, strlen(defaultPath) + 1);
    if (rc != EOK) {
        tloge("strncpy_s failed %" PUBLIC "d\n", rc);
        return -1;
    }
    return 0;
}

static int32_t GetTransientDir(char* path, size_t pathLen)
{
    return GetPathStorage(path, pathLen, "SFS_PARTITION_TRANSIENT");
}

static int32_t GetPersistentDir(char* path, size_t pathLen)
{
    return GetPathStorage(path, pathLen, "SFS_PARTITION_PERSISTENT");
}

#define USER_PATH_SIZE 10
static int32_t JoinFileNameTransient(const char *name, char *path, size_t pathLen)
{
    errno_t rc;
    int32_t ret;
    uint32_t userId = GetCurrentUserId();

    ret = GetTransientDir(path, pathLen);
    if (ret != 0) {
        return ret;
    }

    if (userId != 0) {
        char userPath[USER_PATH_SIZE] = { 0 };
        rc = snprintf_s(userPath, sizeof(userPath), sizeof(userPath) - 1, "%u/", userId);
        if (rc == -1) {
            tloge("snprintf_s failed %" PUBLIC "d\n", rc);
            return -1;
        }

        rc = strncat_s(path, pathLen, SFS_PARTITION_USER_SYMLINK, strlen(SFS_PARTITION_USER_SYMLINK));
        if (rc != EOK) {
            tloge("strncat_s failed %" PUBLIC "d\n", rc);
            return -1;
        }

        rc = strncat_s(path, pathLen, userPath, strlen(userPath));
        if (rc != EOK) {
            tloge("strncat_s failed %" PUBLIC "d\n", rc);
            return -1;
        }

        if (strlen(name) <= strlen(SFS_PARTITION_TRANSIENT)) {
            tloge("name length is too small\n");
            return -1;
        }
        rc = strncat_s(path, pathLen, name + strlen(SFS_PARTITION_TRANSIENT),
                       (strlen(name) - strlen(SFS_PARTITION_TRANSIENT)));
        if (rc != EOK) {
            tloge("strncat_s failed %" PUBLIC "d\n", rc);
            return -1;
        }
    } else {
        rc = strncat_s(path, pathLen, name, strlen(name));
        if (rc != EOK) {
            tloge("strncat_s failed %" PUBLIC "d\n", rc);
            return -1;
        }
    }

    return 0;
}

static int32_t GetDefaultDir(char *path, size_t pathLen)
{
    errno_t rc;
    int32_t ret;

    ret = GetPersistentDir(path, pathLen);
    if (ret != 0) {
        return ret;
    }

    rc = strncat_s(path, pathLen, SFS_PARTITION_PERSISTENT, strlen(SFS_PARTITION_PERSISTENT));
    if (rc != EOK) {
        tloge("strncat_s failed %" PUBLIC "d\n", rc);
        return -1;
    }
    return 0;
}

#ifdef CONFIG_BACKUP_PARTITION
#define BACKUP_PARTITION_ENV             "BACKUP_PARTITION"
static int GetBackupPath(char *path, size_t pathLen)
{
    const char *envPath = getenv(BACKUP_PARTITION_ENV);
    if (envPath == NULL) {
        tloge("databack envPath is NULL.\n");
        return -1;
    }

    return CheckEnvPath(envPath, path, pathLen);
}

static bool IsBackupDir(const char *path)
{
    char secBackupDir[FILE_NAME_MAX_BUF] = { 0 };
    int32_t ret;

    ret = GetBackupPath(secBackupDir, FILE_NAME_MAX_BUF);
    if (ret != 0)
        return false;
    if (path == strstr(path, secBackupDir))
        return true;
    return false;
}

static int32_t DoJoinBackupFileName(const char *name, char *path, size_t pathLen)
{
    int32_t ret;
    errno_t rc;
    ret = GetBackupPath(path, pathLen);
    if (ret != 0)
        return ret;

    if (name != strstr(name, SFS_PARTITION_TRANSIENT) && name != strstr(name, SFS_PARTITION_PERSISTENT)) {
        rc = strncat_s(path, pathLen, SFS_PARTITION_PERSISTENT, strlen(SFS_PARTITION_PERSISTENT));
        if (rc != EOK) {
            tloge("strncat_s backup file default prefix failed %" PUBLIC "d\n", rc);
            return -1;
        }
    }

    rc = strncat_s(path, pathLen, name, strlen(name));
    if (rc != EOK) {
        tloge("strncat_s backup file name failed %" PUBLIC "d\n", rc);
        return -1;
    }
    return 0;
}
#endif

static int32_t DoJoinFileName(const char *name, char *path, size_t pathLen)
{
    errno_t rc;
    int32_t ret;

    if (name == strstr(name, SFS_PARTITION_TRANSIENT_PERSO) || name == strstr(name, SFS_PARTITION_TRANSIENT_PRIVATE)) {
        ret = GetTransientDir(path, pathLen);
    } else if (name == strstr(name, SFS_PARTITION_PERSISTENT)) {
        ret = GetPersistentDir(path, pathLen);
    } else {
        ret = GetDefaultDir(path, pathLen);
    }

    if (ret != 0) {
        tloge("get dir failed %" PUBLIC "d\n", ret);
        return -1;
    }

    rc = strncat_s(path, pathLen, name, strlen(name));
    if (rc != EOK) {
        tloge("strncat_s failed %" PUBLIC "d\n", rc);
        return -1;
    }

    return 0;
}

static int32_t JoinFileNameForStorageCE(const char *name, char *path, size_t pathLen)
{
    errno_t rc;
    char temp[FILE_NAME_MAX_BUF] = { '\0' };
    char *nameTemp               = temp;
    char *nameWithoutUserId      = NULL;
    char *idString               = NULL;

    rc = memcpy_s(nameTemp, FILE_NAME_MAX_BUF, name, strlen(name));
    if (rc != EOK) {
        tloge("copy failed");
        return -1;
    }

    idString = strtok_r(nameTemp, "/", &nameWithoutUserId);
    if (idString == NULL) {
        tloge("the name %" PUBLIC "s does not match th rule as userid/xxx\n", name);
        return -1;
    }

    rc = strncpy_s(path, pathLen, SEC_STORAGE_DATA_CE, sizeof(SEC_STORAGE_DATA_CE));
    if (rc != EOK) {
        tloge("strncpy_s failed %" PUBLIC "d\n", rc);
        return -1;
    }

    rc = strncat_s(path, pathLen, idString, strlen(idString));
    if (rc != EOK) {
        tloge("strncat_s failed %" PUBLIC "d\n", rc);
        return -1;
    }

    rc = strncat_s(path, pathLen, SEC_STORAGE_DATA_CE_SUFFIX_DIR, sizeof(SEC_STORAGE_DATA_CE_SUFFIX_DIR));
    if (rc != EOK) {
        tloge("strncat_s failed %" PUBLIC "d\n", rc);
        return -1;
    }

    rc = strncat_s(path, pathLen, nameWithoutUserId, strlen(nameWithoutUserId));
    if (rc != EOK) {
        tloge("strncat_s failed %" PUBLIC "d\n", rc);
        return -1;
    }

    return 0;
}

static int32_t JoinFileName(const char *name, bool isBackup, char *path, size_t pathLen)
{
    int32_t ret = -1;
    uint32_t storageId = GetCurrentStorageId();

    if (CheckFileNameAndPath(name, path) != 0) {
        return ret;
    }

    if (storageId == TEE_OBJECT_STORAGE_CE) {
        ret = JoinFileNameForStorageCE(name, path, pathLen);
    } else {
#ifdef CONFIG_BACKUP_PARTITION
        if (isBackup)
            return DoJoinBackupFileName(name, path, pathLen);
#endif
        /*
        * If the path name does not start with sec_storage or sec_storage_data,
        * add sec_storage str for the path
        */
        if (name == strstr(name, SFS_PARTITION_TRANSIENT)) {
            ret = JoinFileNameTransient(name, path, pathLen);
        } else {
            ret = DoJoinFileName(name, path, pathLen);
        }
    }

    tlogv("joined path done\n");
    (void)isBackup;
    return ret;
}

static bool IsDataDir(const char *path, bool isUsers)
{
    char secDataDir[FILE_NAME_MAX_BUF] = { 0 };
    int32_t ret;
    errno_t rc;

    ret = GetTransientDir(secDataDir, FILE_NAME_MAX_BUF);
    if (ret != 0) {
        return false;
    }
    if (isUsers) {
        rc = strncat_s(secDataDir, FILE_NAME_MAX_BUF, SFS_PARTITION_USER_SYMLINK, strlen(SFS_PARTITION_USER_SYMLINK));
    } else {
        rc = strncat_s(secDataDir, FILE_NAME_MAX_BUF, SFS_PARTITION_TRANSIENT, strlen(SFS_PARTITION_TRANSIENT));
    }
    if (rc != EOK) {
        return false;
    }
    if (path == strstr(path, secDataDir)) {
        return true;
    }
    return false;
}

static bool IsRootDir(const char *path)
{
    char secRootDir[FILE_NAME_MAX_BUF] = { 0 };
    int32_t ret;
    errno_t rc;

    ret = GetPersistentDir(secRootDir, FILE_NAME_MAX_BUF);
    if (ret != 0) {
        return false;
    }
    rc = strncat_s(secRootDir, FILE_NAME_MAX_BUF, SFS_PARTITION_PERSISTENT, strlen(SFS_PARTITION_PERSISTENT));
    if (rc != EOK) {
        return false;
    }
    if (path == strstr(path, secRootDir)) {
        return true;
    }

    return false;
}

static bool IsValidFilePath(const char *path)
{
    if (IsDataDir(path, false) || IsDataDir(path, true) || IsRootDir(path) ||
#ifdef CONFIG_BACKUP_PARTITION
        IsBackupDir(path) ||
#endif
        (path == strstr(path, SEC_STORAGE_DATA_CE))) {
        return true;
    }
    tloge("path is invalid\n");
    return false;
}

static uint32_t GetRealFilePath(const char *originPath, char *trustPath, size_t tPathLen)
{
    char *retPath = realpath(originPath, trustPath);
    if (retPath == NULL) {
        /* the file may be not exist, will create after */
        if ((errno != ENOENT) && (errno != EACCES)) {
            tloge("get realpath failed: %" PUBLIC "d\n", errno);
            return (uint32_t)errno;
        }
        /* check origin path */
        if (!IsValidFilePath(originPath)) {
            tloge("origin path is invalid\n");
            return ENFILE;
        }
        errno_t rc = strncpy_s(trustPath, tPathLen, originPath, strlen(originPath));
        if (rc != EOK) {
            tloge("strncpy_s failed %" PUBLIC "d\n", rc);
            return EPERM;
        }
    } else {
        /* check real path */
        if (!IsValidFilePath(trustPath)) {
            tloge("path is invalid\n");
            return ENFILE;
        }
    }
    return 0;
}

static int32_t UnlinkRecursive(const char *name);
static int32_t UnlinkRecursiveDir(const char *name)
{
    bool fail         = false;
    char dn[PATH_MAX] = { 0 };
    errno_t rc;

    /* a directory, so open handle */
    DIR *dir = opendir(name);
    if (dir == NULL) {
        tloge("dir open failed\n");
        return -1;
    }

    /* recurse over components */
    errno = 0;

    struct dirent *de = readdir(dir);

    while (de != NULL) {
        if (strncmp(de->d_name, "..", sizeof("..")) == 0 || strncmp(de->d_name, ".", sizeof(".")) == 0) {
            de = readdir(dir);
            continue;
        }
        rc = snprintf_s(dn, sizeof(dn), sizeof(dn) - 1, "%s/%s", name, de->d_name);
        if (rc == -1) {
            tloge("snprintf_s failed %" PUBLIC "d\n", rc);
            fail = true;
            break;
        }

        if (UnlinkRecursive(dn) < 0) {
            tloge("loop UnlinkRecursive() failed, there are read-only file\n");
            fail = true;
            break;
        }
        errno = 0;
        de    = readdir(dir);
    }

    /* in case readdir or UnlinkRecursive failed */
    if (fail || errno < 0) {
        int32_t save = errno;
        closedir(dir);
        errno = save;
        tloge("fail is %" PUBLIC "d, errno is %" PUBLIC "d\n", fail, errno);
        return -1;
    }

    /* close directory handle */
    if (closedir(dir) < 0) {
        tloge("closedir failed, errno is %" PUBLIC "d\n", errno);
        return -1;
    }

    /* delete target directory */
    if (rmdir(name) < 0) {
        tloge("rmdir failed, errno is %" PUBLIC "d\n", errno);
        return -1;
    }
    return 0;
}

static int32_t UnlinkRecursive(const char *name)
{
    struct stat st;

    /* is it a file or directory? */
    if (lstat(name, &st) < 0) {
        tloge("lstat failed, errno is %" PUBLIC "x\n", errno);
        return -1;
    }

    /* a file, so unlink it */
    if (!S_ISDIR(st.st_mode)) {
        if (unlink(name) < 0) {
            tloge("unlink failed, errno is %" PUBLIC "d\n", errno);
            return -1;
        }
        return 0;
    }

    return UnlinkRecursiveDir(name);
}

static int32_t IsFileExist(const char *name)
{
    struct stat statbuf;

    if (name == NULL) {
        return 0;
    }
    if (stat(name, &statbuf) != 0) {
        if (errno == ENOENT) { /* file not exist */
            tloge("file stat failed\n");
            return 0;
        }
        return 1;
    }

    return 1;
}

#ifdef CONFIG_BACKUP_PARTITION
#define SFS_BACKUP_FILE_SUFFIX  ".bk"

static int32_t CopyFromOldFile(const char *name, const char *path, size_t pathLen)
{
    char oldNameBuff[FILE_NAME_MAX_BUF] = { 0 };
    int32_t ret = JoinFileName(name, false, oldNameBuff, sizeof(oldNameBuff));
    if (ret != 0) {
        if (ret == ENOENT) {
            tlogw("main partition file dont exist \n");
            return 0;
        }
        return -1;
    }

    if (IsFileExist(oldNameBuff) == 0) {
        return 0;
    }

    if (strncmp(path, oldNameBuff, strlen(oldNameBuff) + 1) == 0) {
        tlogd("name of bk file is the same as main file, needn't copy\n");
        return 0;
    }

    if (CreateDir(path, pathLen) != 0) {
        return -1;
    }
    tlogw("try copy bk file from main partition to backup partition, %" PUBLIC "s\n", name);
    ret = CopyFile((char *)oldNameBuff, path);
    if (ret != 0) {
        tloge("copy file failed: %" PUBLIC "d\n", errno);
        return -1;
    }

    ret = UnlinkRecursive((char *)oldNameBuff);
    /* if old file delete failed, OpenWork failed */
    if (ret != 0) {
        tloge("delete old file failed: %" PUBLIC "d\n", errno);
        (void)UnlinkRecursive(path);
        return -1;
    }

    return 0;
}

static int32_t DeleteBackupFile(char *nameBuff, size_t nameLen)
{
    char oldNameBuff[FILE_NAME_MAX_BUF] = { 0 };
    errno_t rc = memcpy_s(oldNameBuff, sizeof(oldNameBuff), nameBuff, nameLen);
    if (rc != EOK) {
        tloge("memcpy_s failed %" PUBLIC "d \n", rc);
        return -1;
    }

    rc = strcat_s(oldNameBuff, sizeof(oldNameBuff), SFS_BACKUP_FILE_SUFFIX);
    if (rc != EOK) {
        tloge("strcat_s failed %" PUBLIC "d \n", rc);
        return -1;
    }

    if (IsFileExist(oldNameBuff) == 0)
        return 0;

    tlogd("try unlink exist backfile in main partition\n");
    if (unlink((char *)oldNameBuff) < 0) {
        tloge("unlink failed, errno is %" PUBLIC "d\n", errno);
        return -1;
    }
    return 0;
}
#endif

static uint32_t DoOpenFile(const char *path, struct SecStorageType *transControl)
{
    char trustPath[PATH_MAX] = { 0 };

    uint32_t rRet = GetRealFilePath(path, trustPath, sizeof(trustPath));
    if (rRet != 0) {
        tloge("get real path failed. err=%" PUBLIC "u\n", rRet);
        return rRet;
    }

    FILE *pFile = fopen(trustPath, transControl->args.open.mode);
    if (pFile == NULL) {
        tloge("open file with flag %" PUBLIC "s failed: %" PUBLIC "d\n", transControl->args.open.mode, errno);
        return (uint32_t)errno;
    }
    ChownSecStorage(trustPath, true);
    int32_t ret = AddOpenFile(pFile);
    if (ret != 0) {
        tloge("add OpenedFile failed\n");
        (void)fclose(pFile);
        return ENOMEM;
    }
    transControl->ret = fileno(pFile); /* return fileno */
    return 0;
}

#ifndef CONFIG_SMART_LOCK_PLATFORM
static int32_t CheckPartitionReady(const char *mntDir)
{
    int err;
    struct statfs rootStat, secStorageStat;
    err = statfs("/", &rootStat);
    if (err != 0) {
        tloge("statfs root fail, errno=%" PUBLIC "d\n", errno);
        return err;
    }

    err = statfs(mntDir, &secStorageStat);
    if (err != 0) {
        tloge("statfs mntDir[%" PUBLIC "s] fail, errno=%" PUBLIC "d\n", mntDir, errno);
        return err;
    }
    tlogd("statfs root.f_blocks=%" PUBLIC "llx, mntDir.f_blocks=%" PUBLIC "llx\n",
        (unsigned long long)(rootStat.f_blocks), (unsigned long long)(secStorageStat.f_blocks));

    return rootStat.f_blocks != secStorageStat.f_blocks;
}
#endif

static inline uint64_t GetTimeStampUs(void)
{
    struct timespec ts = { 0 };
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * USEC_PER_SEC + ts.tv_nsec / NSEC_PER_USEC;
}

static int CheckOpenWorkValid(struct SecStorageType *transControl, bool isBackup, char *nameBuff, size_t nameLen)
{
    int ret = 0;
    if (transControl->cmd == SEC_CREATE) {
        /* create a exist file, remove it at first */
        errno_t rc = strncpy_s(transControl->args.open.mode,
            sizeof(transControl->args.open.mode), "w+", sizeof("w+"));
        if (rc != EOK) {
            tloge("strncpy_s failed %" PUBLIC "d\n", rc);
            ret = ENOENT;
        }
    } else {
#ifdef CONFIG_BACKUP_PARTITION
        if (isBackup && CopyFromOldFile((char *)(transControl->args.open.name), nameBuff, nameLen) != 0) {
            tloge("failed to copy bk file from main partition to backup partition\n");
            return ENOENT;
        }
#endif

        if (IsFileExist(nameBuff) == 0) {
            /* open a nonexist file, return fail */
            tloge("file is not exist, open failed\n");
            ret = ENOENT;
        }
    }
    (void)isBackup;
    (void)nameLen;
    return ret;
}

static void OpenWork(struct SecStorageType *transControl)
{
    uint32_t error;
    char nameBuff[FILE_NAME_MAX_BUF] = { 0 };
    bool isBackup = false;

    SetCurrentUserId(transControl->userId);
    SetCurrentStorageId(transControl->storageId);

    tlogw("sec storage: cmd=%" PUBLIC "d, file=%" PUBLIC "s\n",
        transControl->cmd, (char *)(transControl->args.open.name));

#ifdef CONFIG_BACKUP_PARTITION
    isBackup = transControl->isBackup;
#endif
    if (JoinFileName((char *)(transControl->args.open.name), isBackup, nameBuff, sizeof(nameBuff)) != 0) {
        transControl->ret = -1;
        return;
    }
#ifdef CONFIG_BACKUP_PARTITION
    if (transControl->cmd == SEC_CREATE && DeleteBackupFile(nameBuff, sizeof(nameBuff)) != 0) {
        tloge("create failed, bk file exist and delete it failed\n");
        transControl->ret = -1;
        return;
    }
#endif

#ifndef CONFIG_SMART_LOCK_PLATFORM
    if (strstr((char *)nameBuff, SFS_PARTITION_PERSISTENT) != NULL) {
        if (CheckPartitionReady("/sec_storage") <= 0) {
            tloge("check /sec_storage partition_ready failed ----------->\n");
            transControl->ret = -1;
            return;
        }
    }
#endif

    if (CheckOpenWorkValid(transControl, isBackup, nameBuff, sizeof(nameBuff)) != 0) {
        error = ENOENT;
        goto ERROR;
    }

    /* mkdir -p for new create files */
    if (CreateDir(nameBuff, sizeof(nameBuff)) != 0) {
        error = (uint32_t)errno;
        goto ERROR;
    }

    error = DoOpenFile(nameBuff, transControl);
    if (error != 0) {
        goto ERROR;
    }

    return;

ERROR:
    transControl->ret   = -1;
    transControl->error = error;
    return;
}

static void CloseWork(struct SecStorageType *transControl)
{
    struct OpenedFile *selFile = NULL;

    tlogv("sec storage : close\n");

    if (FindOpenFile(transControl->args.close.fd, &selFile) != 0) {
        int32_t ret = fclose(selFile->file);
        if (ret == 0) {
            tlogv("close file %" PUBLIC "d success\n", transControl->args.close.fd);
            DelOpenFile(selFile);
            free(selFile);
            selFile = NULL;
            (void)selFile;
        } else {
            tloge("close file %" PUBLIC "d failed: %" PUBLIC "d\n", transControl->args.close.fd, errno);
            transControl->error = (uint32_t)errno;
        }
        transControl->ret = ret;
    } else {
        tloge("can't find opened file(fileno = %" PUBLIC "d)\n", transControl->args.close.fd);
        transControl->ret   = -1;
        transControl->error = EBADF;
    }
}

static void ReadWork(struct SecStorageType *transControl)
{
    struct OpenedFile *selFile = NULL;

    tlogv("sec storage : read count = %" PUBLIC "u\n", transControl->args.read.count);

    if (FindOpenFile(transControl->args.read.fd, &selFile) != 0) {
        size_t count = fread((void *)(transControl->args.read.buffer), 1, transControl->args.read.count, selFile->file);
        transControl->ret = (int32_t)count;

        if (count < transControl->args.read.count) {
            if (feof(selFile->file)) {
                transControl->ret2 = 0;
                tlogv("read end of file\n");
            } else {
                transControl->ret2  = -1;
                transControl->error = (uint32_t)errno;
                tloge("read file failed: %" PUBLIC "d\n", errno);
            }
        } else {
            transControl->ret2 = 0;
            tlogv("read file success, content len=%" PUBLIC "zu\n", count);
        }
    } else {
        transControl->ret   = 0;
        transControl->ret2  = -1;
        transControl->error = EBADF;
        tloge("can't find opened file(fileno = %" PUBLIC "d)\n", transControl->args.read.fd);
    }
}

static void WriteWork(struct SecStorageType *transControl)
{
    struct OpenedFile *selFile = NULL;

    tlogv("sec storage : write count = %" PUBLIC "u\n", transControl->args.write.count);

    if (FindOpenFile(transControl->args.write.fd, &selFile) != 0) {
        size_t count = fwrite((void *)(transControl->args.write.buffer), 1,
                              transControl->args.write.count, selFile->file);
        if (count < transControl->args.write.count) {
            tloge("write file failed: %" PUBLIC "d\n", errno);
            transControl->ret   = (int32_t)count;
            transControl->error = (uint32_t)errno;
            return;
        }

        if (transControl->ret2 == SEC_WRITE_SSA) {
            if (fflush(selFile->file) != 0) {
                tloge("fflush file failed: %" PUBLIC "d\n", errno);
                transControl->ret   = 0;
                transControl->error = (uint32_t)errno;
            } else {
                transControl->ret = (int32_t)count;
            }
        } else {
            transControl->ret   = (int32_t)count;
            transControl->error = 0;
        }
    } else {
        tloge("can't find opened file(fileno = %" PUBLIC "d)\n", transControl->args.write.fd);
        transControl->ret   = 0;
        transControl->error = EBADF;
    }
}

static void SeekWork(struct SecStorageType *transControl)
{
    struct OpenedFile *selFile = NULL;

    tlogv("sec storage : seek offset=%" PUBLIC "d, whence=%" PUBLIC "u\n",
        transControl->args.seek.offset, transControl->args.seek.whence);

    if (FindOpenFile(transControl->args.seek.fd, &selFile) != 0) {
        int32_t ret = fseek(selFile->file, transControl->args.seek.offset, (int32_t)transControl->args.seek.whence);
        if (ret) {
            tloge("seek file failed: %" PUBLIC "d\n", errno);
            transControl->error = (uint32_t)errno;
        } else {
            tlogv("seek file success\n");
        }
        transControl->ret = ret;
    } else {
        tloge("can't find opened file(fileno = %" PUBLIC "d)\n", transControl->args.seek.fd);
        transControl->ret   = -1;
        transControl->error = EBADF;
    }
}

static void RemoveWork(struct SecStorageType *transControl)
{
    char nameBuff[FILE_NAME_MAX_BUF] = { 0 };
    bool isBackup = false;

    tlogw("sec storage: remove=%" PUBLIC "s\n", (char *)(transControl->args.remove.name));

    SetCurrentUserId(transControl->userId);
    SetCurrentStorageId(transControl->storageId);

#ifdef CONFIG_BACKUP_PARTITION
    isBackup = transControl->isBackup;
#endif
    if (JoinFileName((char *)(transControl->args.remove.name), isBackup, nameBuff, sizeof(nameBuff)) == 0) {
        int32_t ret = UnlinkRecursive(nameBuff);
        if (ret != 0) {
            tloge("remove file failed: %" PUBLIC "d\n", errno);
            transControl->error = (uint32_t)errno;
        } else {
            tlogv("remove file success\n");
        }
        transControl->ret = ret;
    } else {
        transControl->ret = -1;
    }
}

static void TruncateWork(struct SecStorageType *transControl)
{
    char nameBuff[FILE_NAME_MAX_BUF] = { 0 };
    bool isBackup = false;

    tlogv("sec storage : truncate, len=%" PUBLIC "u\n", transControl->args.truncate.len);

    SetCurrentUserId(transControl->userId);
    SetCurrentStorageId(transControl->storageId);
#ifdef CONFIG_BACKUP_PARTITION
    isBackup = transControl->isBackup;
#endif
    if (JoinFileName((char *)(transControl->args.truncate.name), isBackup, nameBuff, sizeof(nameBuff)) == 0) {
        int32_t ret = truncate(nameBuff, (long)transControl->args.truncate.len);
        if (ret != 0) {
            tloge("truncate file failed: %" PUBLIC "d\n", errno);
            transControl->error = (uint32_t)errno;
        } else {
            tlogv("truncate file success\n");
        }
        transControl->ret = ret;
    } else {
        transControl->ret = -1;
    }
}

static void RenameWork(struct SecStorageType *transControl)
{
    char nameBuff[FILE_NAME_MAX_BUF]  = { 0 };
    char nameBuff2[FILE_NAME_MAX_BUF] = { 0 };
    bool oldIsBackup = false;
    bool newIsBackup = false;

    SetCurrentUserId(transControl->userId);
    SetCurrentStorageId(transControl->storageId);

    tlogw("sec storage: rename, old=%" PUBLIC "s, new=%" PUBLIC "s\n", (char *)(transControl->args.open.name),
        (char *)(transControl->args.rename.buffer) + transControl->args.rename.oldNameLen);

#ifdef CONFIG_BACKUP_PARTITION
    oldIsBackup = transControl->isBackup;
    newIsBackup = transControl->isBackupExt;
#endif
    int32_t joinRet1 = JoinFileName((char *)(transControl->args.rename.buffer), oldIsBackup, nameBuff,
        sizeof(nameBuff));
    int32_t joinRet2 = JoinFileName((char *)(transControl->args.rename.buffer) + transControl->args.rename.oldNameLen,
                                    newIsBackup, nameBuff2, sizeof(nameBuff2));
    if (joinRet1 == 0 && joinRet2 == 0) {
        int32_t ret = rename(nameBuff, nameBuff2);
        if (ret != 0) {
            tloge("rename file failed: %" PUBLIC "d\n", errno);
            transControl->error = (uint32_t)errno;
        } else {
            tlogv("rename file success\n");
        }
        transControl->ret = ret;
    } else {
        transControl->ret = -1;
    }
}

#define MAXBSIZE 65536

static int32_t DoCopy(int32_t fromFd, int32_t toFd)
{
    int32_t ret;
    ssize_t rcount;
    ssize_t wcount;

    char *buf = (char *)malloc(MAXBSIZE * sizeof(char));
    if (buf == NULL) {
        tloge("malloc buf failed\n");
        return -1;
    }

    rcount = read(fromFd, buf, MAXBSIZE);
    while (rcount > 0) {
        wcount = write(toFd, buf, (size_t)rcount);
        if (rcount != wcount || wcount == -1) {
            tloge("write file failed: %" PUBLIC "d\n", errno);
            ret = -1;
            goto OUT;
        }
        rcount = read(fromFd, buf, MAXBSIZE);
    }

    if (rcount < 0) {
        tloge("read file failed: %" PUBLIC "d\n", errno);
        ret = -1;
        goto OUT;
    }

    /* fsync memory from kernel to disk */
    ret = fsync(toFd);
    if (ret != 0) {
        tloge("CopyFile:fsync file failed: %" PUBLIC "d\n", errno);
        goto OUT;
    }

OUT:
    free(buf);
    return ret;
}

static int32_t CopyFile(const char *fromPath, const char *toPath)
{
    struct stat fromStat;
    char realFromPath[PATH_MAX] = { 0 };
    char realToPath[PATH_MAX]   = { 0 };

    uint32_t rRet = GetRealFilePath(fromPath, realFromPath, sizeof(realFromPath));
    if (rRet != 0) {
        tloge("get real from path failed. err=%" PUBLIC "u\n", rRet);
        return -1;
    }

    rRet = GetRealFilePath(toPath, realToPath, sizeof(realToPath));
    if (rRet != 0) {
        tloge("get real to path failed. err=%" PUBLIC "u\n", rRet);
        return -1;
    }

    int32_t fromFd = tee_open(realFromPath, O_RDONLY, 0);
    if (fromFd == -1) {
        tloge("open file failed: %" PUBLIC "d\n", errno);
        return -1;
    }

    int32_t ret = fstat(fromFd, &fromStat);
    if (ret == -1) {
        tloge("stat file failed: %" PUBLIC "d\n", errno);
        tee_close(&fromFd);
        return ret;
    }
    
    tlogw("Copy file size: %" PUBLIC "u bytes\n", (uint32_t)fromStat.st_size);
    int32_t toFd = tee_open(realToPath, O_WRONLY | O_TRUNC | O_CREAT, fromStat.st_mode);
    if (toFd == -1) {
        tloge("stat file failed: %" PUBLIC "d\n", errno);
        tee_close(&fromFd);
        return -1;
    }

    ret = DoCopy(fromFd, toFd);
    if (ret != 0) {
        tloge("do copy failed\n");
    } else {
        ChownSecStorage((char *)realToPath, true);
    }

    tee_close(&fromFd);
    tee_close(&toFd);
    return ret;
}

static void CopyWork(struct SecStorageType *transControl)
{
    char fromPath[FILE_NAME_MAX_BUF] = { 0 };
    char toPath[FILE_NAME_MAX_BUF]   = { 0 };
    bool fromIsBackup = false;
    bool toIsBackup = false;

    SetCurrentUserId(transControl->userId);
    SetCurrentStorageId(transControl->storageId);

#ifdef CONFIG_BACKUP_PARTITION
    fromIsBackup = transControl->isBackup;
    toIsBackup   = transControl->isBackupExt;
#endif
    int32_t joinRet1 = JoinFileName((char *)(transControl->args.cp.buffer), fromIsBackup, fromPath, sizeof(fromPath));
    int32_t joinRet2 = JoinFileName((char *)(transControl->args.cp.buffer) + transControl->args.cp.fromPathLen,
        toIsBackup, toPath, sizeof(toPath));
    tlogw("sec storage: copy, oldpath=%" PUBLIC "s, newpath = %" PUBLIC "s\n",(char *)(transControl->args.cp.buffer),
        (char *)(transControl->args.cp.buffer) + transControl->args.cp.fromPathLen);
    if (joinRet1 == 0 && joinRet2 == 0) {
#ifdef CONFIG_BACKUP_PARTITION
        if (IsFileExist(toPath) == 0) {
            tlogd("copy_to path not exist, mkdir it.\n");
            if (CreateDir(toPath, sizeof(toPath)) != 0) {
                transControl->ret = -1;
                return;
            }
        }
#endif
        int32_t ret = CopyFile(fromPath, toPath);
        if (ret != 0) {
            tloge("copy file failed: %" PUBLIC "d\n", errno);
            transControl->error = (uint32_t)errno;
        } else {
            tlogv("copy file success\n");
        }
        transControl->ret = ret;
    } else {
        transControl->ret = -1;
    }
}

static void FileInfoWork(struct SecStorageType *transControl)
{
    struct OpenedFile *selFile = NULL;
    struct stat statBuff;

    tlogv("sec storage : file info\n");

    transControl->args.info.fileLen = transControl->args.info.curPos = 0;

    if (FindOpenFile(transControl->args.info.fd, &selFile) != 0) {
        int32_t ret = fstat(transControl->args.info.fd, &statBuff);
        if (ret == 0) {
            transControl->args.info.fileLen = (uint32_t)statBuff.st_size;
            transControl->args.info.curPos  = (uint32_t)ftell(selFile->file);
        } else {
            tloge("fstat file failed: %" PUBLIC "d\n", errno);
            transControl->error = (uint32_t)errno;
        }
        transControl->ret = ret;
    } else {
        transControl->ret   = -1;
        transControl->error = EBADF;
    }
}

static void FileAccessWork(struct SecStorageType *transControl)
{
    int32_t ret;
    bool isBackup = false;

    tlogv("sec storage : file access\n");

    if (transControl->cmd == SEC_ACCESS) {
        char nameBuff[FILE_NAME_MAX_BUF] = { 0 };
        SetCurrentUserId(transControl->userId);
        SetCurrentStorageId(transControl->storageId);

#ifdef CONFIG_BACKUP_PARTITION
        isBackup = transControl->isBackup;
#endif
        if (JoinFileName((char *)(transControl->args.access.name), isBackup, nameBuff, sizeof(nameBuff)) == 0) {
            ret = access(nameBuff, transControl->args.access.mode);
            if (ret < 0) {
                tloge("access file mode %" PUBLIC "d failed: %" PUBLIC "d\n", transControl->args.access.mode, errno);
            }
            transControl->ret   = ret;
            transControl->error = (uint32_t)errno;
        } else {
            transControl->ret = -1;
        }
    } else {
        ret = access((char *)(transControl->args.access.name), transControl->args.access.mode);
        if (ret < 0) {
            tloge("access2 file mode %" PUBLIC "d failed: %" PUBLIC "d\n", transControl->args.access.mode, errno);
        }
        transControl->ret   = ret;
        transControl->error = (uint32_t)errno;
    }
}

static void FsyncWork(struct SecStorageType *transControl)
{
    struct OpenedFile *selFile = NULL;

    tlogw("sec storage : file fsync\n");

    /* opened file */
    if (transControl->args.fsync.fd != 0 && FindOpenFile(transControl->args.fsync.fd, &selFile) != 0) {
        /* first,flush memory from user to kernel */
        int32_t ret = fflush(selFile->file);
        if (ret != 0) {
            tloge("fsync:fflush file failed: %" PUBLIC "d\n", errno);
            transControl->ret   = -1;
            transControl->error = (uint32_t)errno;
            return;
        }
        tlogw("fflush file %" PUBLIC "d success\n", transControl->args.fsync.fd);

        /* second,fsync memory from kernel to disk */
        int32_t fd  = fileno(selFile->file);
        ret = fsync(fd);
        if (ret != 0) {
            tloge("fsync:fsync file failed: %" PUBLIC "d\n", errno);
            transControl->ret   = -1;
            transControl->error = (uint32_t)errno;
            return;
        }

        transControl->ret = 0;
        tlogw("fsync file %" PUBLIC "d success\n", transControl->args.fsync.fd);
    } else {
        tloge("can't find opened file(fileno = %" PUBLIC "d)\n", transControl->args.fsync.fd);
        transControl->ret   = -1;
        transControl->error = EBADF;
    }
}

#define KBYTE 1024
static void DiskUsageWork(struct SecStorageType *transControl)
{
    struct statfs st;
    uint32_t dataRemain;
    uint32_t secStorageRemain;
    char nameBuff[FILE_NAME_MAX_BUF] = { 0 };

    tlogv("sec storage : disk usage\n");
    if (GetTransientDir(nameBuff, FILE_NAME_MAX_BUF) != 0)
        goto ERROR;
    if (statfs((const char*)nameBuff, &st) < 0) {
        tloge("statfs /secStorageData failed, err=%" PUBLIC "d\n", errno);
        goto ERROR;
    }
    dataRemain = (uint32_t)st.f_bfree * (uint32_t)st.f_bsize / KBYTE;

    if (GetPersistentDir(nameBuff, FILE_NAME_MAX_BUF) != 0) {
        tloge("get persistent dir error\n");
        goto ERROR;
    }
    if (strncat_s(nameBuff, FILE_NAME_MAX_BUF, SFS_PARTITION_PERSISTENT, strlen(SFS_PARTITION_PERSISTENT)) != EOK) {
        tloge("strncat_s error\n");
        goto ERROR;
    }
    if (statfs((const char*)nameBuff, &st) < 0) {
        tloge("statfs /secStorage failed, err=%" PUBLIC "d\n", errno);
        goto ERROR;
    }
    secStorageRemain = (uint32_t)st.f_bfree * (uint32_t)st.f_bsize / KBYTE;

    transControl->ret                       = 0;
    transControl->args.diskUsage.data       = dataRemain;
    transControl->args.diskUsage.secStorage = secStorageRemain;
    return;

ERROR:
    transControl->ret   = -1;
    transControl->error = (uint32_t)errno;
}

static void DeleteAllWork(struct SecStorageType *transControl)
{
    int32_t ret;
    char path[FILE_NAME_MAX_BUF] = { 0 };
    char *pathIn                 = (char *)(transControl->args.deleteAll.path);
    SetCurrentUserId(transControl->userId);

    tlogv("sec storage : delete path, userid:%" PUBLIC "d\n", transControl->userId);

    ret = DoJoinFileName(pathIn, path, sizeof(path));
    if (ret != EOK) {
        tloge("join name failed %" PUBLIC "d\n", ret);
        transControl->ret = -1;
        return;
    }

    tlogv("sec storage : joint delete path\n");

    ret = UnlinkRecursive(path);
    if (ret != 0) {
        tloge("delete file failed: %" PUBLIC "d\n", errno);
        transControl->error = (uint32_t)errno;
    } else {
        tloge("delete file success\n");
    }
    transControl->ret = ret;
}

typedef void (*FsWorkFunc)(struct SecStorageType *transControl);

struct FsWorkTbl {
    enum FsCmdType cmd;
    FsWorkFunc fn;
};

static const struct FsWorkTbl g_fsWorkTbl[] = {
    { SEC_OPEN, OpenWork },           { SEC_CLOSE, CloseWork },
    { SEC_READ, ReadWork },           { SEC_WRITE, WriteWork },
    { SEC_SEEK, SeekWork },           { SEC_REMOVE, RemoveWork },
    { SEC_TRUNCATE, TruncateWork },   { SEC_RENAME, RenameWork },
    { SEC_CREATE, OpenWork },         { SEC_INFO, FileInfoWork },
    { SEC_ACCESS, FileAccessWork },   { SEC_ACCESS2, FileAccessWork },
    { SEC_FSYNC, FsyncWork },         { SEC_CP, CopyWork },
    { SEC_DISKUSAGE, DiskUsageWork }, { SEC_DELETE_ALL, DeleteAllWork },
};

static int FsWorkEventHandle(struct SecStorageType *transControl, int32_t fsFd)
{
    int32_t ret;
    uint64_t tsStart, tsEnd;

    ret = ioctl(fsFd, (int32_t)TC_NS_CLIENT_IOCTL_WAIT_EVENT, AGENT_FS_ID);
    if (ret != 0) {
        tloge("fs agent wait event failed, errno = %" PUBLIC "d\n", errno);
        return ret;
    }

    tlogv("fs agent wake up and working!!\n");
    tsStart = GetTimeStampUs();

    if ((transControl->cmd < SEC_MAX) && (g_fsWorkTbl[transControl->cmd].fn != NULL)) {
        g_fsWorkTbl[transControl->cmd].fn(transControl);
    } else {
        tloge("fs agent error cmd:transControl->cmd=%" PUBLIC "x\n", transControl->cmd);
    }

    tsEnd = GetTimeStampUs();
    if (tsEnd - tsStart > FSCMD_TIMEOUT_US) {
        tlogw("fs agent timeout, cmd=0x%" PUBLIC "x, cost=%" PUBLIC "llums\n",
            transControl->cmd, (tsEnd - tsStart) / USEC_PER_MSEC);
    }

    __asm__ volatile("isb");
    __asm__ volatile("dsb sy");

    transControl->magic = AGENT_FS_ID;

    __asm__ volatile("isb");
    __asm__ volatile("dsb sy");

    ret = ioctl(fsFd, (int32_t)TC_NS_CLIENT_IOCTL_SEND_EVENT_RESPONSE, AGENT_FS_ID);
    if (ret != 0) {
        tloge("fs agent send reponse failed\n");
        return ret;
    }

    return 0;
}

void *FsWorkThread(void *control)
{
    struct SecStorageType *transControl = NULL;
    int32_t ret;
    int32_t fsFd;

    if (control == NULL) {
        return NULL;
    }
    transControl = control;

    fsFd = GetFsFd();
    if (fsFd == -1) {
        tloge("fs is not open\n");
        return NULL;
    }

    transControl->magic = AGENT_FS_ID;

#ifdef CONFIG_FSWORK_THREAD_ELEVATE_PRIO
    if (setpriority(0, 0, FS_AGENT_THREAD_PRIO) != 0) {
        tloge("set fs work thread priority fail, err=%" PUBLIC "d\n", errno);
    }
#endif

    while (1) {
        tlogv("++ fs agent loop ++\n");
        ret = FsWorkEventHandle(transControl, fsFd);
        if (ret != 0) {
            break;
        }
        tlogv("-- fs agent loop --\n");
    }

    return NULL;
}

void SetFileNumLimit(void)
{
    struct rlimit rlim, rlimNew;

    int32_t rRet = getrlimit(RLIMIT_NOFILE, &rlim);
    if (rRet == 0) {
        rlimNew.rlim_cur = rlimNew.rlim_max = FILE_NUM_LIMIT_MAX;
        if (setrlimit(RLIMIT_NOFILE, &rlimNew) != 0) {
            rlimNew.rlim_cur = rlimNew.rlim_max = rlim.rlim_max;
            (void)setrlimit(RLIMIT_NOFILE, &rlimNew);
        }
    } else {
        tloge("getrlimit error is 0x%" PUBLIC "x, errno is %" PUBLIC "x", rRet, errno);
    }
}
