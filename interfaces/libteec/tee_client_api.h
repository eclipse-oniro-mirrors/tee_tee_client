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

#ifndef TEE_CLIENT_API_H
#define TEE_CLIENT_API_H
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
 * @file tee_client_api.h
 *
 * @brief 客户端应用访问安全应用相关接口定义。
 *
 * <p>使用示例：
 * <p> 1.打开TEE环境：调用TEEC_InitializeContext初始化TEE环境；
 * <p> 2.打开会话：调用TEEC_OpenSession，参数为安全应用TA的UUID；
 * <p> 3.发送命令：调用TEEC_InvokeCommand向安全应用发送命令；
 * <p> 4.关闭会话：调用接口TEEC_CloseSession，关闭会话；
 * <p> 5.关闭TEE环境：调用接口TEEC_FinalizeContext，关闭TEE环境。
 *
 * @since 8
 */

#include <string.h>
#include "tee_client_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 用于计算非安全世界与安全世界传递参数的数值
 *
 * @since 8
 */
#define TEEC_PARAM_TYPES(param0Type, param1Type, param2Type, param3Type) \
    ((param3Type) << 12 | (param2Type) << 8 | (param1Type) << 4 | (param0Type))

/**
 * @brief 用于计算paramTypes中字段index的数值
 *
 * @since 8
 */
#define TEEC_PARAM_TYPE_GET(paramTypes, index) \
    (((paramTypes) >> (4*(index))) & 0x0F)

/**
 * @brief 初始化TEE环境
 *
 * @par 描述:
 * 初始化路径为name的TEE环境，参数name可以为空，
 * 初始化TEE环境是打开会话、发送命令的基础，
 * 初始化成功后，客户端应用与TEE建立一条连接。
 *
 * @param name [IN] TEE环境路径
 * @param context [IN/OUT] context指针，安全世界环境句柄
 *
 * @return #TEEC_SUCCESS 初始化TEE环境成功
 *         #TEEC_ERROR_BAD_PARAMETERS 参数不正确，name不正确或context为空
 *         #TEEC_ERROR_GENERIC 系统可用资源不足等原因
 * @since 8
 */
TEEC_Result TEEC_InitializeContext(const char *name, TEEC_Context *context);

/**
 * @brief 关闭TEE环境
 *
 * @par 描述:
 * 关闭context指向的TEE环境，断开客户端应用与TEE环境的连接
 *
 * @param context [IN/OUT] 指向已初始化成功的TEE环境
 *
 * @return 无
 * @since 8
 */
void TEEC_FinalizeContext(TEEC_Context *context);

/**
 * @brief 打开会话
 *
 * @par 描述:
 * 在指定的TEE环境context下，为客户端应用与UUID为destination的安全应用建立一条连接，
 * 连接方式是connectionMethod，连接数据是connectionData，传递的数据包含在opetation里。
 * 打开会话成功后，输出参数session是对该连接的一个描述；
 * 如果打开会话失败，输出参数returnOrigin为错误来源。
 *
 * @param context [IN/OUT] 指向已初始化成功的TEE环境
 * @param session [OUT] 指向会话，取值不能为空
 * @param destination [IN] 安全应用的UUID，一个安全应用拥有唯一的UUID
 * @param connectionMethod [IN] 连接方式，取值范围为#TEEC_LoginMethod
 * @param connectionData [IN] 与连接方式相对应的连接数据，
 * 如果连接方式为#TEEC_LOGIN_PUBLIC、#TEEC_LOGIN_USER、
 * #TEEC_LOGIN_USER_APPLICATION、#TEEC_LOGIN_GROUP_APPLICATION，连接数据取值必须为空，
 * 如果连接方式为#TEEC_LOGIN_GROUP、#TEEC_LOGIN_GROUP_APPLICATION，
 * 连接数据必须指向类型为uint32_t的数据，此数据表示客户端应用期望连接的组用户
 * @param operation [IN/OUT] 客户端应用与安全应用传递的数据
 * @param returnOrigin [IN/OUT] 错误来源，取值范围为#TEEC_ReturnCodeOrigin
 *
 * @return #TEEC_SUCCESS 打开会话成功
 *         #TEEC_ERROR_BAD_PARAMETERS 参数不正确，参数context为空或session为空或destination为空
 *         #TEEC_ERROR_ACCESS_DENIED 系统调用权限访问失败
 *         #TEEC_ERROR_OUT_OF_MEMORY 系统可用资源不足
 *         #TEEC_ERROR_TRUSTED_APP_LOAD_ERROR 加载安全应用失败
 *         其它返回值参考 #TEEC_ReturnCode
 * @since 8
 */
TEEC_Result TEEC_OpenSession(TEEC_Context *context, TEEC_Session *session, const TEEC_UUID *destination,
    uint32_t connectionMethod, const void *connectionData, TEEC_Operation *operation, uint32_t *returnOrigin);

/**
 * @brief 关闭会话
 *
 * @par 描述:
 * 关闭session指向的会话，断开客户端应用与安全应用的连接
 *
 * @param session [IN/OUT] 指向已成功打开的会话
 *
 * @return 无
 * @since 8
 */
void TEEC_CloseSession(TEEC_Session *session);

/**
 * @brief 发送命令
 *
 * @par 描述:
 * 在指定的会话session里，由客户端应用向安全应用发送命令commandID，
 * 发送的数据为operation，如果发送命令失败，输出参数returnOrigin为错误来源
 *
 * @param session [IN/OUT] 指向已打开成功的会话
 * @param commandID [IN] 安全应用支持的命令ID，由安全应用定义
 * @param operation [IN/OUT] 包含了客户端应用向安全应用发送的数据内容
 * @param returnOrigin [IN/OUT] 错误来源，取值范围为#TEEC_ReturnCodeOrigin
 *
 * @return #TEEC_SUCCESS 发送命令成功
 *         #TEEC_ERROR_BAD_PARAMETERS 参数不正确，参数session为空或参数operation格式不正确
 *         #TEEC_ERROR_ACCESS_DENIED 系统调用权限访问失败
 *         #TEEC_ERROR_OUT_OF_MEMORY 系统可用资源不足
 *         其它返回值参考 #TEEC_ReturnCode
 * @since 8
 */
TEEC_Result TEEC_InvokeCommand(TEEC_Session *session, uint32_t commandID,
    TEEC_Operation *operation, uint32_t *returnOrigin);

/**
 * @brief 注册共享内存
 *
 * @par 描述:
 * 在指定的TEE环境context内注册共享内存sharedMem，
 * 通过注册的方式获取共享内存来实现零拷贝，需要操作系统的支持，
 * 目前的实现中，该方式不能实现零拷贝
 *
 * @param context [IN/OUT] 已初始化成功的TEE环境
 * @param sharedMem [IN/OUT] 共享内存指针，共享内存所指向的内存不能为空、大小不能为零
 *
 * @return #TEEC_SUCCESS 发送命令成功
 *         #TEEC_ERROR_BAD_PARAMETERS 参数不正确，参数context为空或sharedMem为空，或共享内存所指向的内存为空
 * @since 8
 */
TEEC_Result TEEC_RegisterSharedMemory(TEEC_Context *context, TEEC_SharedMemory *sharedMem);

/**
 * @brief 申请共享内存
 *
 * @par 描述:
 * 在指定的TEE环境context内申请共享内存sharedMem，
 * 通过共享内存可以实现非安全世界与安全世界传递数据时的零拷贝，需要操作系统的支持，
 * 目前的实现中，该方式不能实现零拷贝
 *
 * @attention 如果入参sharedMem的size域设置为0，函数会返回成功，但无法使用这块
 * 共享内存，因为这块内存既没有地址也没有大小
 * @param context [IN/OUT] 已初始化成功的TEE环境
 * @param sharedMem [IN/OUT] 共享内存指针，共享内存的大小不能为零
 *
 * @return #TEEC_SUCCESS 发送命令成功
 *         #TEEC_ERROR_BAD_PARAMETERS 参数不正确，参数context为空或sharedMem为空
 *         #TEEC_ERROR_OUT_OF_MEMORY 系统可用资源不足，分配失败
 * @since 8
 */
TEEC_Result TEEC_AllocateSharedMemory(TEEC_Context *context, TEEC_SharedMemory *sharedMem);

/**
 * @brief 释放共享内存
 *
 * @par 描述:
 * 释放已注册成功的的或已申请成功的共享内存sharedMem
 *
 * @attention 如果是通过#TEEC_AllocateSharedMemory方式获取的共享内存，
 * 释放时会回收这块内存；如果是通过#TEEC_RegisterSharedMemory方式
 * 获取的共享内存，释放时不会回收共享内存所指向的本地内存
 * @param sharedMem [IN/OUT] 指向已注册成功或申请成功的共享内存
 *
 * @return 无
 * @since 8
 */
void TEEC_ReleaseSharedMemory(TEEC_SharedMemory *sharedMem);

/**
 * @brief cancel API
 *
 * @par 描述:
 * 取消掉一个正在运行的open Session或者是一个invoke command
 * 发送一个cancel的signal后立即返回
 *
 * @attention 此操作仅仅是发送一个cancel的消息，是否进行cancel操作由TEE或TA决定，目前为空实现
 * @param operation [IN/OUT] 包含了客户端应用向安全应用发送的数据内容
 *
 * @return 无
 * @since 8
 */
void TEEC_RequestCancellation(TEEC_Operation *operation);

#ifdef __cplusplus
}
#endif
/** @} */
#endif
