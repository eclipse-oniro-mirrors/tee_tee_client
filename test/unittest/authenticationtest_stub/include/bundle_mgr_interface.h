/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef MOCK_FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLEMGR_BUNDLE_MGR_INTERFACE_H
#define MOCK_FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLEMGR_BUNDLE_MGR_INTERFACE_H

#include <string>
#include <cwchar>
#include "iremote_broker.h"

namespace OHOS {
namespace AppExecFwk {

enum Constants {
    BASE_USER_RANGE = 200000,
};

class IBundleMgr : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.appexecfwk.BundleMgr");
    /**
     * @brief Obtains the application UID based on the given bundle name and user ID.
     * @param bundleName Indicates the bundle name of the application.
     * @param userId Indicates the user ID.
     * @return Returns the uid if successfully obtained; returns -1 otherwise.
     */
    virtual int GetUidByBundleName(const std::string &bundleName, const int userId)
    {
        return -1;
    }
    /**
     * @brief Obtains the application UID based on the given bundle name and user ID.
     * @param bundleName Indicates the bundle name of the application.
     * @param userId Indicates the user ID.
     * @param userId Indicates the app Index.
     * @return Returns the uid if successfully obtained; returns -1 otherwise.
     */
    virtual int32_t GetUidByBundleName(const std::string &bundleName, const int32_t userId, int32_t appIndex)
    {
        return -1;
    }
    /**
     * @brief Obtains the application ID based on the given bundle name and user ID.
     * @param bundleName Indicates the bundle name of the application.
     * @param userId Indicates the user ID.
     * @return Returns the application ID if successfully obtained; returns empty string otherwise.
     */
    virtual std::string GetAppIdByBundleName(const std::string &bundleName, const int userId)
    {
        printf("enter IbundleImgr GetAppIdByBundleName");
        if (userId == 0) {
            std::string tmp (4097, 's'); // 4097 is The max length of caInfo->certs
            return tmp;
        } else if (userId == 1) { // 2 is flag for cover branchs
            return "Authentication_Test";
        } else {
            return "";
        }

        return "";
    }
    /**
     * @brief Obtains the formal name associated with the given UID.
     * @param uid Indicates the uid.
     * @param name Indicates the obtained formal name.
     * @return Returns ERR_OK if execute success; returns errCode otherwise.
     */
    virtual int32_t GetNameForUid(const int uid, std::string &name)
    {
        return -1;
    }
};
}
}
#endif // MOCK_FOUNDATION_APPEXECFWK_INTERFACES_INNERKITS_APPEXECFWK_CORE_INCLUDE_BUNDLEMGR_BUNDLE_MGR_INTERFACE_H