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

#include "teeclientsocket_fuzzer.h"

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <sys/socket.h>
#include <sys/un.h>
#include <securec.h>
#include "tee_log.h"
#include "tee_client_inner.h"
#include "tee_client_socket.h"
namespace OHOS {
    #define TC_NS_SOCKET_NAME "#tc_ns_socket"
    bool TeeClientTeeSrvIpcProcCmdFuzzTest(const uint8_t *data, size_t size)
    {
        int ret;
        int rc;
        uint32_t len;
        struct sockaddr_un remote;
        struct msghdr message;
        CaRevMsg revBuffer = { 0 };
        char ctrlBuffer[CMSG_SPACE(sizeof(int))];
        size_t msgLen = size >= sizeof(message) ? sizeof(message) : size;

        if (memset_s(&message, sizeof(message), 0, sizeof(message)) != EOK) {
            return false;
        }
        if (memcpy_s(&message, msgLen - 1, data, msgLen - 1) != EOK) {
            return false;
        }

        (message.msg_iov[0]).iov_base = revBuffer;
        (message.msg_iov[0]).iov_len = sizeof(revBuffer);
        message.msg_control = (void*)ctrlBuffer;
        message.msg_controllen = CMSG_SPACE(sizeof(int));

        int s = socket(AF_UNIX, SOCK_STREAM, 0);
        if (s == -1) {
            tloge("can't open stream socket, errno=%" PUBLIC "d\n", errno);
            return false;
        }

        tlogd("Trying to connect...\n");
        remote.sun_family = AF_UNIX;

        rc = strncpy_s(remote.sun_path, sizeof(remote.sun_path), TC_NS_SOCKET_NAME, sizeof(TC_NS_SOCKET_NAME));
        if (rc != EOK) {
            tloge("strncpy_s failed, rc=%d, errno=%" PUBLIC "d\n", rc, errno);
            close(s);
            return false;
        }
        len = static_cast<uint32_t>((strlen(remote.sun_path) + sizeof(remote.sun_family)));
        remote.sun_path[0] = 0;

        if (connect(s, (struct sockaddr *)&remote, len) == -1) {
            tloge("connect() failed, errno=%" PUBLIC "d\n", errno);
            close(s);
            return false;
        }
        tloge("Connected.\n");

        if (sendmsg(s, &message, 0) < 0) {
            tloge("send message error %" PUBLIC "d \n", errno);
            close(s);
            return false;
        }
        ret = recvmsg(s, &message, 0);
        if (ret <= 0) {
            tloge("send message error %" PUBLIC "d \n", errno);
            close(s);
            return false;
        }
        close(s);
        return true;
    }
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::TeeClientTeeSrvIpcProcCmdFuzzTest(data, size);
    return 0;
}