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

#ifndef TEE_TA_VERSION_CTRL_H
#define TEE_TA_VERSION_CTRL_H

#include <stdint.h>

enum {
    CTRL_TYPE_VENDOR  = 0,
    CTRL_TYPE_SYSTEM,
};

#ifdef __cplusplus
extern "C" {
#endif
bool SetTaVersionCtrl(uint8_t ctrl_type);
void InitTaVersionCtrl(uint8_t ctrl_type);
#ifdef __cplusplus
}
#endif

#endif /* TEE_TA_VERSION_CTRL_H */
