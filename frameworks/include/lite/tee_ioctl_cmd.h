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

#ifndef IOCTL_DEFINE_H
#define IOCTL_DEFINE_H
#include "tee_client_type.h"

#define TC_NS_CLIENT_IOCTL_SES_OPEN_REQ                   _IOW(TC_NS_CLIENT_IOC_MAGIC, 1, TC_NS_ClientContext)
#define TC_NS_CLIENT_IOCTL_SES_CLOSE_REQ                  _IOWR(TC_NS_CLIENT_IOC_MAGIC, 2, TC_NS_ClientContext)
#define TC_NS_CLIENT_IOCTL_SEND_CMD_REQ                   _IOWR(TC_NS_CLIENT_IOC_MAGIC, 3, TC_NS_ClientContext)
#define TC_NS_CLIENT_IOCTL_SHRD_MEM_RELEASE               _IOWR(TC_NS_CLIENT_IOC_MAGIC, 4, unsigned int)
#define TC_NS_CLIENT_IOCTL_WAIT_EVENT                     _IO(TC_NS_CLIENT_IOC_MAGIC, 5)
#define TC_NS_CLIENT_IOCTL_SEND_EVENT_RESPONSE            _IO(TC_NS_CLIENT_IOC_MAGIC, 6)
#define TC_NS_CLIENT_IOCTL_REGISTER_AGENT                 _IOWR(TC_NS_CLIENT_IOC_MAGIC, 7, struct AgentIoctlArgs)
#define TC_NS_CLIENT_IOCTL_UNREGISTER_AGENT               _IO(TC_NS_CLIENT_IOC_MAGIC, 8)
#define TC_NS_CLIENT_IOCTL_LOAD_APP_REQ                   _IOWR(TC_NS_CLIENT_IOC_MAGIC, 9, struct SecLoadIoctlStruct)
#define TC_NS_CLIENT_IOCTL_NEED_LOAD_APP                  _IOWR(TC_NS_CLIENT_IOC_MAGIC, 10, TC_NS_ClientContext)
#define TC_NS_CLIENT_IOCTL_LOAD_APP_EXCEPT                _IOWR(TC_NS_CLIENT_IOC_MAGIC, 11, unsigned int)
#define TC_NS_CLIENT_IOCTL_CANCEL_CMD_REQ                 _IOWR(TC_NS_CLIENT_IOC_MAGIC, 13, TC_NS_ClientContext)
#define TC_NS_CLIENT_IOCTL_LOGIN                          _IO(TC_NS_CLIENT_IOC_MAGIC, 14)
#define TC_NS_CLIENT_IOCTL_TST_CMD_REQ                    _IOWR(TC_NS_CLIENT_IOC_MAGIC, 15, int)
#define TC_NS_CLIENT_IOCTL_SYC_SYS_TIME                   _IOWR(TC_NS_CLIENT_IOC_MAGIC, 17, TC_NS_Time)
#define TC_NS_CLIENT_IOCTL_SET_NATIVE_IDENTITY            _IOWR(TC_NS_CLIENT_IOC_MAGIC, 18, int)
#define TC_NS_CLIENT_IOCTL_LATEINIT                       _IO(TC_NS_CLIENT_IOC_MAGIC, 20)
#define TC_NS_CLIENT_IOCTL_GET_TEE_VERSION                _IOWR(TC_NS_CLIENT_IOC_MAGIC, 21, unsigned int)
#define TC_NS_CLIENT_IOCTL_UNMAP_SHARED_MEM               _IOWR(TC_NS_CLIENT_IOC_MAGIC, 22, unsigned int)

#endif
