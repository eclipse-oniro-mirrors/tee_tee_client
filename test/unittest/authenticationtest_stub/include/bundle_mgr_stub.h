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

#ifndef MOCK_FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLEMGR_BUNDLE_MGR_MINI_STUB_H
#define MOCK_FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLEMGR_BUNDLE_MGR_MINI_STUB_H

#include "bundle_mgr_interface.h"
#include "iremote_stub.h"

namespace OHOS {
namespace AppExecFwk {
class BundleMgrStub : public IRemoteStub<IBundleMgr> {
public:
    BundleMgrStub() = default;
    virtual ~BundleMgrStub() = default;
    int32_t OnRemoteRequest(uint32_t code,
        MessageParcel& data, MessageParcel &reply, MessageOption &option) override
        {
            return 0;
        }
};
} // namespace AppExecFwk
} // namespace OHOS
#endif // MOCK_FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLEMGR_BUNDLE_MGR_MINI_STUB_H
