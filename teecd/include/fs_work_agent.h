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

#ifndef LIBTEEC_FS_WORK_AGENT_H
#define LIBTEEC_FS_WORK_AGENT_H

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include "fs_work_agent_define.h"

#define FILE_NAME_MAX_BUF       256
#define FILE_NUM_LIMIT_MAX      1024
#define KINDS_OF_SSA_MODE       4

#define AID_SYSTEM 1000

#define SFS_PARTITION_PERSISTENT "sec_storage/"

#define SFS_PARTITION_USER_SYMLINK "sec_storage_data_users/"

#define SEC_STORAGE_DATA_USERS  USER_DATA_DIR"sec_storage_data_users/"
#define SEC_STORAGE_DATA_USER_0 USER_DATA_DIR"sec_storage_data_users/0"
#define SEC_STORAGE_DATA_DIR    USER_DATA_DIR"sec_storage_data/"

#define TRANS_BUFF_SIZE (4 * 1024) /* agent transfer share buffer size */

#define SEC_STORAGE_ROOT_DIR      ROOT_DIR SFS_PARTITION_PERSISTENT

/* 0600 only root can read and write sec_storage folder */
#define ROOT_DIR_PERM                   (S_IRUSR | S_IWUSR)
#define SFS_PARTITION_TRANSIENT         "sec_storage_data/"
#define SFS_PARTITION_TRANSIENT_PRIVATE "sec_storage_data/_private"
#define SFS_PARTITION_TRANSIENT_PERSO   "sec_storage_data/_perso"

#define FILE_NAME_INVALID_STR "../" // file name path must not contain ../

#define SEC_STORAGE_DATA_CE         "/data/vendor_ce/"
#define SEC_STORAGE_DATA_ROOT_DIR   ROOT_DIR SFS_PARTITION_TRANSIENT
#define TEE_OBJECT_STORAGE_CE       0x80000002


/* static func declare */
enum FsCmdType {
    SEC_OPEN,
    SEC_CLOSE,
    SEC_READ,
    SEC_WRITE,
    SEC_SEEK,
    SEC_REMOVE,
    SEC_TRUNCATE,
    SEC_RENAME,
    SEC_CREATE,
    SEC_INFO,
    SEC_ACCESS,
    SEC_ACCESS2,
    SEC_FSYNC,
    SEC_CP,
    SEC_DISKUSAGE,
    SEC_DELETE_ALL,
    SEC_MAX
};

enum {
    SEC_WRITE_SLOG,
    SEC_WRITE_SSA,
};

struct SecStorageType {
    enum FsCmdType cmd; /* for s to n */
    int32_t ret;   /* fxxx call's return */
    int32_t ret2;  /* fread: end-of-file or error;fwrite:the sendor is SSA or SLOG */
    uint32_t userId;
    uint32_t storageId;
    uint32_t magic;
    uint32_t error;
    union Args1 {
        struct {
            char mode[KINDS_OF_SSA_MODE];
            uint32_t nameLen;
            uint32_t name[1];
        } open;
        struct {
            int32_t fd;
        } close;
        struct {
            int32_t fd;
            uint32_t count;
            uint32_t buffer[1]; /* the same as name[0] --> name[1] */
        } read;
        struct {
            int32_t fd;
            uint32_t count;
            uint32_t buffer[1];
        } write;
        struct {
            int32_t fd;
            int32_t offset;
            uint32_t whence;
        } seek;
        struct {
            uint32_t nameLen;
            uint32_t name[1];
        } remove;
        struct {
            uint32_t len;
            uint32_t nameLen;
            uint32_t name[1];
        } truncate;
        struct {
            uint32_t oldNameLen;
            uint32_t newNameLen;
            uint32_t buffer[1]; /* old_name + new_name */
        } rename;
        struct {
            uint32_t fromPathLen;
            uint32_t toPathLen;
            uint32_t buffer[1]; /* from_path+to_path */
        } cp;
        struct {
            char mode[KINDS_OF_SSA_MODE];
            uint32_t nameLen;
            uint32_t name[1];
        } create;
        struct {
            int32_t fd;
            uint32_t curPos;
            uint32_t fileLen;
        } info;
        struct {
            int mode;
            uint32_t nameLen;
            uint32_t name[1];
        } access;
        struct {
            int32_t fd;
        } fsync;
        struct {
            uint32_t secStorage;
            uint32_t data;
        } diskUsage;
        struct {
            uint32_t pathLen;
            uint32_t path[1];
        } deleteAll;
    } args;
};

struct OpenedFile {
    FILE *file;
    struct OpenedFile *next;
    struct OpenedFile *prev;
};

int IsUserDataReady(void);
void *FsWorkThread(void *control);
void SetFileNumLimit(void);

#endif
