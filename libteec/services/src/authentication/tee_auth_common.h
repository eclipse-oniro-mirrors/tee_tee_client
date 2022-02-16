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
#include <sys/stat.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_PATH_LENGTH        256
#define CMD_MAX_SIZE           1024

typedef struct {
    uid_t uid;
    pid_t pid;
} CaAuthInfo;

int TeeGetPkgName(int caPid, char *path, size_t pathLen);

#ifdef __cplusplus
}
#endif

#endif
