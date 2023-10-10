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
#ifndef LIBTEEC_TEE_CA_DAEMON_H
#define LIBTEEC_TEE_CA_DAEMON_H
#include <sys/stat.h>
#include "tee_auth_common.h"

typedef struct {
    int magic;
    int status;
    int userid;
    int reserved;
} RecvMsg;

void *CaServerWorkThread(void *dummy);

#endif