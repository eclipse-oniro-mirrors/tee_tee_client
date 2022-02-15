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

#ifndef TEE_CLIENT_CONSTANTS_H
#define TEE_CLIENT_CONSTANTS_H
/**
 * @addtogroup TeeClient
 * @{
 *
 * @brief TEEC_API 客户端(非安全侧)接口。
 *
 * 提供非安全侧(正常模式)下客户端程序访问安全模式下安全应用相关接口。
 *
 * @since 8
 */

/**
 * @file tee_client_constants.h
 *
 * @brief 公共数据及常量定义。
 *
 * @since 8
 */

/**
 * @brief 定义TEEC_Operation中TEEC_Parameter个数。
 *
 * @since 8
 */
#define TEEC_PARAM_NUM 4 /* teec param max number */

/**
 * @brief 函数返回的错误码
 *
 * @since 8
 */
enum TEEC_ReturnCode {
    TEEC_SUCCESS = 0x0,                       /* 函数返回成功 */
    TEEC_ERROR_INVALID_CMD,                   /* 非法命令，安全应用不支持的命令 */
    TEEC_ERROR_SERVICE_NOT_EXIST,             /* 安全应用不存在 */
    TEEC_ERROR_SESSION_NOT_EXIST,             /* 客户端应用与安全应用的连接不存在 */
    TEEC_ERROR_SESSION_MAXIMUM,               /* 安全应用的连接数已满 */
    TEEC_ERROR_REGISTER_EXIST_SERVICE,        /* 注册已经存在的安全应用 */
    TEEC_ERROR_TAGET_DEAD_FATAL,              /* 安全OS框架错误 */
    TEEC_ERROR_READ_DATA,                     /* 读取文件错误 */
    TEEC_ERROR_WRITE_DATA,                    /* 写入文件错误 */
    TEEC_ERROR_TRUNCATE_OBJECT,               /* 截断文件错误 */
    TEEC_ERROR_SEEK_DATA,                     /* 查找文件错误 */
    TEEC_ERROR_FSYNC_DATA,                    /* 同步文件错误 */
    TEEC_ERROR_RENAME_OBJECT,                 /* 重命名文件错误 */
    TEEC_ERROR_TRUSTED_APP_LOAD_ERROR,        /* 打开会话时，加载安全应用失败 */
    TEEC_ERROR_GENERIC = 0xFFFF0000,          /* 通用错误，初始化安全应用失败 */
    TEEC_ERROR_ACCESS_DENIED = 0xFFFF0001,    /* 权限校验失败，打开TEE环境、打开会话和发送命令都会进行权限的校验，
                                                 权限校验不通过会返回此类错误 */
    TEEC_ERROR_CANCEL = 0xFFFF0002,           /* 操作已取消，如果参数的取消标志位已置位，
                                                 再对此参数进行操作时返回此类错误 */
    TEEC_ERROR_ACCESS_CONFLICT = 0xFFFF0003,  /* 并发访问导致权限冲突，
                                                 安全存储服务中对文件的并发访问可能会产生此类错误 */
    TEEC_ERROR_EXCESS_DATA = 0xFFFF0004,      /* 操作包含的数据太多 ，安全应用无法解析 */
    TEEC_ERROR_BAD_FORMAT = 0xFFFF0005,       /* 数据格式不正确，客户端应用填充的参数格式不满足客户端应用与
                                                 安全应用的通信协议，安全应用无法解析 */
    TEEC_ERROR_BAD_PARAMETERS = 0xFFFF0006,   /* 参数无效，入参为空或非法等错误 */
    TEEC_ERROR_BAD_STATE = 0xFFFF0007,        /* 当前状态下的操作无效，请求安全存储服务操作时，
                                                 如果没有初始化安全存储服务，会返回此类错误 */
    TEEC_ERROR_ITEM_NOT_FOUND = 0xFFFF0008,   /* 请求的数据未找到 */
    TEEC_ERROR_NOT_IMPLEMENTED = 0xFFFF0009,  /* 请求的操作存在但暂未实现，请求取消操作时返回此类错误 */
    TEEC_ERROR_NOT_SUPPORTED = 0xFFFF000A,    /* 请求的操作有效但未支持，请求安全加解密服务的一些算法,
                                                 如DSA等时返回此类错误 */
    TEEC_ERROR_NO_DATA = 0xFFFF000B,          /* 数据错误 ，请求的操作找不到对应的数据 */
    TEEC_ERROR_OUT_OF_MEMORY = 0xFFFF000C,    /* 系统可用资源不足，内存申请失败会返回此类错误 */
    TEEC_ERROR_BUSY = 0xFFFF000D,             /* 系统繁忙，系统可能正在独占一些资源 */
    TEEC_ERROR_COMMUNICATION = 0xFFFF000E,    /* 非安全世界应用程序与安全应用通信时发生错误 */
    TEEC_ERROR_SECURITY = 0xFFFF000F,         /* 检测到安全错误，安全世界发生错误 */
    TEEC_ERROR_SHORT_BUFFER = 0xFFFF0010,     /* 内存输入长度小于输出长度，
                                                 使用类型为#TEEC_MEMREF_TEMP_OUTPUT时需要注意此类错误 */
    TEEC_ERROR_MAC_INVALID = 0xFFFF3071,      /* MAC值校验错误 */
    TEEC_ERROR_TARGET_DEAD = 0xFFFF3024,      /* 安全应用崩溃 */
    TEEC_FAIL = 0xFFFF5002                    /* 通用错误 */
};

/**
 * @brief 函数返回错误码的来源
 *
 * @since 8
 */
enum TEEC_ReturnCodeOrigin {
    TEEC_ORIGIN_API = 0x1,          /* 错误码来自客户端API */
    TEEC_ORIGIN_COMMS = 0x2,        /* 错误码来自非安全世界与安全世界的通信 */
    TEEC_ORIGIN_TEE = 0x3,          /* 错误码来自安全世界 */
    TEEC_ORIGIN_TRUSTED_APP = 0x4,  /* 错误码来自安全应用 */
};

/**
 * @brief 共享内存标识
 *
 * @since 8
 */
enum TEEC_SharedMemCtl {
    TEEC_MEM_INPUT = 0x1,        /* 共享内存的数据流是从客户端应用到安全应用 */
    TEEC_MEM_OUTPUT = 0x2,       /* 共享内存的数据流是从安全应用到客户端应用 */
    TEEC_MEM_INOUT = 0x3,        /* 共享内存可在客户端应用与安全应用之间双向传递 */
};

/**
 * @brief 参数类型定义
 *
 * @since 8
 */
enum TEEC_ParamType {
    TEEC_NONE = 0x0,                  /* 参数没有使用 */
    TEEC_VALUE_INPUT = 0x01,          /* 与类型#TEEC_Value相对应，只能作为输入，
                                         数据流是从客户端应用到安全应用 */
    TEEC_VALUE_OUTPUT = 0x02,         /* 与类型#TEEC_Value相对应，只能作为输出，
                                         数据流是从安全应用到客户端应用 */
    TEEC_VALUE_INOUT = 0x03,          /* 与类型#TEEC_Value相对应，既可输入也可输出 */
    TEEC_MEMREF_TEMP_INPUT = 0x05,    /* 与类型#TEEC_TempMemoryReference相对应，
                                         只能作为输入，数据流是从客户端应用到安全应用 */
    TEEC_MEMREF_TEMP_OUTPUT = 0x06,   /* 与类型#TEEC_TempMemoryReference相对应，
                                         只能作为输出，数据流是从安全应用到客户端应用 */
    TEEC_MEMREF_TEMP_INOUT = 0x07,    /* 与类型#TEEC_TempMemoryReference相对应，既可输入也可输出，
                                         可在客户端应用与安全应用之间双向传递 */
    TEEC_MEMREF_WHOLE = 0xc,          /* 与类型#TEEC_RegisteredMemoryReference相对应，引用整块内存，
                                         数据流与所指向的共享内存的标识#TEEC_SharedMemCtl一致 */
    TEEC_MEMREF_PARTIAL_INPUT = 0xd,  /* 与类型#TEEC_RegisteredMemoryReference相对应，只能作为输入，
                                         数据流是从客户端应用到安全应用 */
    TEEC_MEMREF_PARTIAL_OUTPUT = 0xe, /* 与类型#TEEC_RegisteredMemoryReference相对应，只能作为输出，
                                         数据流是从安全应用到客户端应用 */
    TEEC_MEMREF_PARTIAL_INOUT = 0xf   /* 与类型#TEEC_RegisteredMemoryReference相对应，既可输入也可输出，
                                         可在客户端应用与安全应用之间双向传递 */
};

/**
 * @brief Login方式
 *
 * @since 8
*/
enum TEEC_LoginMethod {
    TEEC_LOGIN_PUBLIC = 0x0,            /* 不需要Login数据 */
    TEEC_LOGIN_USER,                    /* 提供用户运行客户端应用的Login数据 */
    TEEC_LOGIN_GROUP,                   /* 提供组用户运行客户端应用的Login数据 */
    TEEC_LOGIN_APPLICATION = 0x4,       /* 提供客户端应用自己的Login数据 */
    TEEC_LOGIN_USER_APPLICATION = 0x5,  /* 提供用户运行客户端应用的Login数据，
                                           以及客户端应用自己的Login数据 */
    TEEC_LOGIN_GROUP_APPLICATION = 0x6, /* 提供组用户运行客户端应用的Login数据，
                                           以及客户端应用自己的Login数据 */
    TEEC_LOGIN_IDENTIFY = 0x7,          /* TEEOS预留LoginMethod */
};

/** @} */
#endif
