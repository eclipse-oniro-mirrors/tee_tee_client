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

#ifndef TEE_AUTH_COMMON_H
#define TEE_AUTH_COMMON_H

#include <stdint.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_PATH_LENGTH        256

#define BUF_MAX_SIZE           4096
#define CMD_MAX_SIZE           1024
#define BACKLOG_LEN            10

typedef enum {
    SYSTEM_CA = 1,
    VENDOR_CA,
    APP_CA,
    SA_CA,
    MAX_CA,
} CaType;

typedef struct {
    uint8_t certs[BUF_MAX_SIZE]; /* for APP_CA\SA_CA */
    CaType type;
    uid_t uid;
    pid_t pid;
} CaAuthInfo;

int TeeGetPkgName(int caPid, char *path, size_t pathLen);

#ifdef __cplusplus
}
#endif

#endif
