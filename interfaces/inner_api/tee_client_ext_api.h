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

#ifndef TEE_CLIENT_EXT_API_H
#define TEE_CLIENT_EXT_API_H
/**
 * @addtogroup TeeClient
 * @{
 *
 * @brief Provides APIs for the client applications (CAs) in the Rich Execution Environment (normal mode) to
 * access the trusted applications (TAs) in a Trusted Execution Environment (TEE).
 *
 * @since 8
 */

/**
 * @file tee_client_ext_api.h
 *
 * @brief Defines extend APIs for CAs to access TAs.
 *
 * <p> Example:
 * <p>1. Initialize a TEE: Call <b>TEEC_InitializeContext</b> to initialize the TEE.
 * <p>2. Open a session: Call <b>TEEC_OpenSession</b> with the Universal Unique Identifier (UUID) of the TA.
 * <p>3. Send a command: Call <b>TEEC_InvokeCommand</b> to send a command to the TA.
 * <p>4. Close the session: Call <b>TEEC_CloseSession</b> to close the session.
 * <p>5. Close the TEE: Call <b>TEEC_FinalizeContext</b> to close the TEE.
 *
 * @since 8
 */

#include "tee_client_type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief CA register an agent for TA communicate with CA.
 *
 *
 * @param agentId [IN] user defined, do not conflict with other agent.
 * @param devFd [OUT] TEE driver fd.
 * @param buffer [OUT] shared memory between CA&TA, size is 4K.
 *
 * @return Returns {@code TEEC_SUCCESS} if the CA is successfully register an agent for TA communicate with CA.
 *         Returns {@code TEEC_ERROR_GENERIC} if error happened.
 * @since 8
 */
TEEC_Result TEEC_EXT_RegisterAgent(uint32_t agentId, int *devFd, void **buffer);

/**
 * @brief CA wait event from TA.
 *
 * when call this interface, CA thread will block until TA send a msg.
 *
 * @param agentId [IN] user registered agent
 * @param devFd [IN] TEE driver fd
 *
 * @return Returns {@code TEEC_SUCCESS} if the CA receive msg from TA success.
 *         Returns {@code TEEC_ERROR_GENERIC} if error happened.
 * @since 8
 */
TEEC_Result TEEC_EXT_WaitEvent(uint32_t agentId, int devFd);

/**
 * @brief CA send response to TA.
 *
 * @param agentId [IN] user registered agent
 * @param devFd [IN] TEE driver fd
 *
 * @return Returns {@code TEEC_SUCCESS} if the CA send cmd success.
 *         Returns {@code TEEC_ERROR_GENERIC} if error happened.
 * @since 8
 */
TEEC_Result TEEC_EXT_SendEventResponse(uint32_t agentId, int devFd);

/**
 * @brief CA unregister an agent.
 *
 * @param agentId [IN] user registered agent
 * @param devFd [IN] TEE driver fd
 * @param buffer [IN] shared mem between CA&TA, TEE will release this buffer and set it to NULL
 *
 * @return Returns {@code TEEC_SUCCESS} if the CA send cmd success.
 *         Returns {@code TEEC_ERROR_GENERIC} if error happened.
 *         Returns {@code TEEC_ERROR_BAD_PARAMETERS} if input parameter is invalid.
 * @since 8
 */
TEEC_Result TEEC_EXT_UnregisterAgent(uint32_t agentId, int devFd, void **buffer);

/**
 * @brief CA sends a secfile to TEE
 *
 * @param path [IN] path of the secfile
 * @param session [IN] session beturn CA&TA
 *
 * @return Returns {@code TEEC_SUCCESS} if the CA send the secfile success.
 *         Returns {@code TEEC_ERROR_GENERIC} if error happened.
 *         Returns {@code TEEC_ERROR_BAD_PARAMETERS} if input parameter is invalid.
 * @since 8
 */
TEEC_Result TEEC_SendSecfile(const char *path, TEEC_Session *session);

/**
 * @brief Get the tee version.
 *
 * @return Returns {@code 0} if get the tee version failed.
 *         Returns {@code > 0} if get the version success.
 * @since 8
 */
uint32_t TEEC_GetTEEVersion(void);

#ifdef __cplusplus
}
#endif

#endif
