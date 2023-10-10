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

#ifndef TEE_AUTH_SYSTEM_H
#define TEE_AUTH_SYSTEM_H

#include <stdint.h>
#include "tee_auth_common.h"

#ifdef __cplusplus
extern "C" {
#endif
int32_t ConstructCaAuthInfo(uint32_t tokenID, CaAuthInfo *caInfo);
int32_t TEEGetNativeSACaInfo(const CaAuthInfo *caInfo, uint8_t *buf, uint32_t bufLen);
#ifdef __cplusplus
}
#endif

#endif