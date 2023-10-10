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
#ifndef LIBTEEC_EXT_API_H
#define LIBTEEC_EXT_API_H

#include <stdint.h>
#include "tee_auth_common.h"

#define TC_NS_SOCKET_NAME        "#tc_ns_socket"

typedef struct {
    int cmd;
    CaAuthInfo caAuthInfo;
} CaRevMsg;

int CaDaemonConnectWithCaInfo(const CaAuthInfo *caInfo, int cmd);

#endif