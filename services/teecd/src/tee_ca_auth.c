/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2022. All rights reserved.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include "tee_ca_auth.h"
#include <sys/ioctl.h> /* for ioctl */
#include "securec.h"
#include "tc_ns_client.h"
#include "tee_client_type.h"
#include "tee_log.h"
#include "tee_auth_common.h"
#include "tee_get_native_cert.h"
#include "tee_ca_daemon.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "teecd_auth"

static int GetLoginInfo(const struct ucred *cr, int fd, uint8_t *buf, unsigned int bufLen)
{
    int ret;

    ret = TeeGetNativeCert(cr->pid, cr->uid, &bufLen, buf);
    if (ret != 0) {
        tloge("CERT check failed<%d>\n", ret);
        /* Inform the driver the cert could not be set */
        ret = ioctl(fd, TC_NS_CLIENT_IOCTL_LOGIN, NULL);
        if (ret != 0) {
            tloge("Failed to set login information for client err=%d!\n", ret);
        }
        return -1;
    }

    return ret;
}

int SendLoginInfo(const struct ucred *cr, const CaRevMsg *caRevInfo, int fd)
{
    int ret;
    unsigned int bufLen = BUF_MAX_SIZE;

    if (cr == NULL || caRevInfo == NULL) {
        tloge("bad parameters\n");
        return -1;
    }

    uint8_t *buf = (uint8_t *)malloc(bufLen);
    if (buf == NULL) {
        tloge("malloc fail.\n");
        return -1;
    }
    ret = memset_s(buf, bufLen, 0, bufLen);
    if (ret != EOK) {
        tloge("memset failed, ret=0x%x\n", ret);
        goto END;
    }

    ret = GetLoginInfo(cr, fd, buf, bufLen);
    if (ret != 0) {
        tloge("get cert failed\n");
        goto END;
    }

    ret = ioctl(fd, TC_NS_CLIENT_IOCTL_LOGIN, buf);
    if (ret != 0) {
        tloge("Failed set login info for client err=%d!\n", ret);
    }

END:
    free(buf);
    return ret;
}

int RecvCaMsg(int socket, CaRevMsg *caInfo)
{
    struct iovec iov[1];
    struct msghdr message;
    fd_set fds;
    struct timeval timeout = { 3, 0 }; /* 3s timeout */
    int ret;

    if (caInfo == NULL) {
        tloge("bad parameter\n");
        return -1;
    }

    errno_t rc = memset_s(&message, sizeof(message), 0, sizeof(struct msghdr));
    if (rc != EOK) {
        tloge("message memset_s failed\n");
        return -1;
    }

    message.msg_name            = NULL;
    message.msg_namelen         = 0;
    message.msg_flags           = 0;
    message.msg_iov             = iov;
    message.msg_iovlen          = 1;
    message.msg_control         = NULL;
    message.msg_controllen      = 0;
    message.msg_iov[0].iov_base = caInfo;
    message.msg_iov[0].iov_len  = sizeof(CaRevMsg);

    FD_ZERO(&fds);
    FD_SET(socket, &fds);
    ret = select(socket + 1, &fds, NULL, NULL, &timeout);
    if (ret <= 0) {
        tloge("teecd socket timeout or err, err=%d.\n", errno);
        return -1;
    }
    ret = (int)recvmsg(socket, &message, 0);
    if (ret <= 0) {
        tloge("tee ca daemon recvmsg failed. \n");
        return -1;
    }
    return 0;
}