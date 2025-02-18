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

#include "tee_file.h"

#define TEE_FD_TAG 0xD005B00
int tee_open(const char* pathname, int flags, mode_t mode)
{
    if (pathname == NULL) {
        return -1;
    }
    int fd = -1;
    if (mode == 0) {
        fd = open(pathname, flags);
    } else {
        fd = open(pathname, flags, mode);
    }
#ifdef ENABLE_FDSAN_CHECK
    if (fd >= 0) {
        fdsan_exchange_owner_tag(fd, 0, TEE_FD_TAG);
    }
#endif
    return fd;
}

void tee_close(int *fd)
{
    if (fd == NULL || *fd < 0) {
        return;
    }
#ifdef ENABLE_FDSAN_CHECK
    fdsan_close_with_tag(*fd, TEE_FD_TAG);
#else
    close(*fd);
#endif
    *fd = -1;
    return;
}

