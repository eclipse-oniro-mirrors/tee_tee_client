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

#ifndef TCU_AUTHENTICATION_H
#define TCU_AUTHENTICATION_H

#include <stdint.h>

enum {
    HASH_TYPE_VENDOR  = 0,
    HASH_TYPE_SYSTEM,
    HASH_TYPE_WHOLE,
};

#ifdef __cplusplus
extern "C" {
#endif
int TcuAuthentication(uint8_t hash_type);
#ifdef __cplusplus
}
#endif

#endif /* TCU_AUTHENTICATION */