/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef MOCK_FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLEMGR_BUNDLE_MGR_MINI_PROXY_H
#define MOCK_FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLEMGR_BUNDLE_MGR_MINI_PROXY_H

#include <string>
#include <iostream>

#include "bundle_mgr_interface.h"
#include "iremote_proxy.h"

namespace OHOS {
const int BUNDLE_MGR_SERVICE_SYS_ABILITY_ID = 401;
namespace AppExecFwk {

class BundleMgrMiniProxy : public IRemoteProxy<IBundleMgr> {
public:
    explicit BundleMgrMiniProxy(const sptr<IRemoteObject> &impl) : IRemoteProxy<IBundleMgr>(impl) {}
    virtual ~BundleMgrMiniProxy() override {}

    ErrCode GetNameForUid(const int uid, std::string &name) override
    {
        return 0;
    }

    std::string GetAppIdByBundleName(const std::string &bundleName, const int userId) override
    {
        return "";
    }

    int GetUidByBundleName(const std::string &bundleName, const int userId) override
    {
        return 0;
    }

    int32_t GetUidByBundleName(const std::string &bundleName, const int32_t userId, int32_t appIndex) override
    {
        return 0;
    }
private:
    static inline BrokerDelegator<BundleMgrMiniProxy> delegator_;
};

}  // namespace AppExecFwk
}  // namespace OHOS
#endif  // MOCK_FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLEMGR_BUNDLE_MGR_MINI_PROXY_H
