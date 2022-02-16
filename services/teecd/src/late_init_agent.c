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

#include "late_init_agent.h"
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "fs_work_agent.h"
#include "tc_ns_client.h"
#include "tee_log.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "teecd_agent"

void *InitLateWorkThread(void *dummy)
{
    (void)dummy;
    unsigned int index            = 0;
    struct timespec ts;
    ts.tv_sec  = 0;
    ts.tv_nsec = SLEEP_TIME;

    tlogd("now start to late init\n");

    int fd = open(TC_NS_CLIENT_DEV_NAME, O_RDWR);
    if (fd < 0) {
        tloge("open tee client dev failed, fd is %d\n", fd);
        return NULL;
    }
    while (true) {
        (void)nanosleep(&ts, NULL);
        if (IsUserDataReady() == 1) {
            index = FS_LATE_INIT;
            break;
        }
        tloge("userdata is not ready, sleep!\n");
    }

    int ret = ioctl(fd, (int)TC_NS_CLIENT_IOCTL_LATEINIT, index);
    if (ret) {
        tloge("failed to set late init, errno = %d\n", errno);
    }

    close(fd);
    return NULL;
}
