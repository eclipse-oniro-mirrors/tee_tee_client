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

#ifndef CA_DAEMON_IPC_INTERFACE_CODE_H
#define CA_DAEMON_IPC_INTERFACE_CODE_H

/* SAID: 8001 */
namespace OHOS {
namespace CaDaemon {
enum class CadaemonOperationInterfaceCode {
        INIT_CONTEXT = 0,
        FINAL_CONTEXT,
        OPEN_SESSION,
        CLOSE_SESSION,
        INVOKE_COMMND,
        REGISTER_MEM,
        ALLOC_MEM,
        RELEASE_MEM,
        SET_CALL_BACK,
        SEND_SECFILE,
        GET_TEE_VERSION
    };
}
}
#endif
