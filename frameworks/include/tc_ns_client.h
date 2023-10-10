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

#ifndef _TC_NS_CLIENT_H_
#define _TC_NS_CLIENT_H_
#include "tee_client_type.h"
#include "tee_ioctl_cmd.h"

#ifndef ZERO_SIZE_PTR
#define ZERO_SIZE_PTR       ((void *)16)
#define ZERO_OR_NULL_PTR(x) ((unsigned long)(x) <= (unsigned long)ZERO_SIZE_PTR)
#endif

#define UUID_SIZE      16

#define TC_NS_CLIENT_IOC_MAGIC 't'
#define TC_NS_CLIENT_DEV       "tc_ns_client"
#define TC_NS_CLIENT_DEV_NAME  "/dev/tc_ns_client"
#define TC_PRIVATE_DEV_NAME  "/dev/tc_private"
#define TUI_LISTEN_PATH "/sys/kernel/tui/c_state"

enum ConnectCmd {
    GET_FD,
    GET_TEEVERSION,
};
typedef struct {
    unsigned int method;
    unsigned int mdata;
} TC_NS_ClientLogin;

typedef union {
    struct {
        unsigned int buffer;
        unsigned int buffer_h_addr;
        unsigned int offset;
        unsigned int h_offset;
        unsigned int size_addr;
        unsigned int size_h_addr;
    } memref;
    struct {
        unsigned int a_addr;
        unsigned int a_h_addr;
        unsigned int b_addr;
        unsigned int b_h_addr;
    } value;
} TC_NS_ClientParam;

typedef struct {
    unsigned int code;
    unsigned int origin;
} TC_NS_ClientReturn;

typedef struct {
    unsigned char uuid[UUID_SIZE];
    unsigned int session_id;
    unsigned int cmd_id;
    TC_NS_ClientReturn returns;
    TC_NS_ClientLogin login;
    TC_NS_ClientParam params[TEEC_PARAM_NUM];
    unsigned int paramTypes;
    bool started;
    unsigned int callingPid;
    unsigned int file_size;
    union {
        char *file_buffer;
        unsigned long long file_addr;
    };
} TC_NS_ClientContext;

typedef struct {
    uint32_t seconds;
    uint32_t millis;
} TC_NS_Time;

enum SecFileType {
    LOAD_TA = 0,
    LOAD_SERVICE,
    LOAD_LIB,
    LOAD_DYNAMIC_DRV,
};

struct SecFileInfo {
    enum SecFileType fileType;
    uint32_t fileSize;
    int32_t secLoadErr;
};
struct SecLoadIoctlStruct {
    struct SecFileInfo secFileInfo;
    TEEC_UUID uuid;
    union {
        char *fileBuffer;
        struct {
            uint32_t file_addr;
            uint32_t file_h_addr;
        } memref;
    };
}__attribute__((packed));

struct AgentIoctlArgs {
    uint32_t id;
    uint32_t bufferSize;
    union {
        void *buffer;
        unsigned long long addr;
    };
};

#endif
