/*
 * Copyright (C) 2023 Huawei Technologies Co., Ltd.
 * Licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include "tee_auth_system.h"
#include "tee_auth_common.h"
#include "tee_log.h"
#include "accesstoken_kit.h"
#include "openssl/evp.h"
#include <securec.h>
#include <cstring>
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "if_system_ability_manager.h"
#include "system_ability_definition.h"
#include "bundle_mgr_mini_proxy.h"

#define HAP_APPID_SPLIT_CHA    '_'
#define BASE_NUM_TWO   2
#define BASE_NUM_THREE  3
#define BASE_NUM_FOUR  4
#define MAX_BASE64_PADDING_LEN  2
#define MAX_PUBKEY_LEN  512
#define UNCOMPRESSED_PUBKEY_PREFIX 0x04

using namespace std;
using namespace OHOS;
using namespace OHOS::Security::AccessToken;

static int32_t Base64Decode(string& encodedStr, unsigned char *decodedStr, uint32_t *decodedLen)
{
    size_t encodedLen = encodedStr.length();
    if (encodedLen == 0 || encodedLen % BASE_NUM_FOUR != 0) {
        tloge("invaild based64 string, size %" PUBLIC "zu\n", encodedLen);
        return -1;
    }
    if (*decodedLen < ((encodedLen / BASE_NUM_FOUR) * BASE_NUM_THREE)) {
        tloge("decode string len too short, %" PUBLIC "zu, %" PUBLIC "u\n", encodedLen, (unsigned int)*decodedLen);
        return -1;
    }

    int32_t ret = EVP_DecodeBlock(decodedStr, (const unsigned char*)encodedStr.c_str(), (int)encodedLen);
    if (ret < 0) {
        tloge("EVP DecodeBlock failed, ret %" PUBLIC "d\n", ret);
        return -1;
    }

    uint32_t padLen = 0;
    for (uint32_t i = 1; i <= BASE_NUM_FOUR; i++) {
        if (encodedStr.at(encodedLen - i) == '=') {
            padLen++;
        } else {
            break;
        }
    }

    if (padLen > MAX_BASE64_PADDING_LEN) {
        tloge("invaild base64 padding len, %" PUBLIC "u\n", padLen);
        return -1;
    }

    if (ret == 0 || ret <= static_cast<int32_t>(padLen)) {
        tloge("base64 decoded failed, decoded len %" PUBLIC "u, pad len %" PUBLIC "u\n", ret, padLen);
        return -1;
    }

    *decodedLen = ret - padLen;
    return 0;
}

static int32_t FillEccHapCaInfo(string& packageName, const char *pubKey, uint32_t pubKeyLen, CaAuthInfo *caInfo)
{
    /* certs format: packageNameLen || packageName || pubKeyLen || pubKey (xLen || x || yLen || y) */
    uint64_t hapInfoSize = sizeof(uint32_t) + packageName.length() +
        sizeof(uint32_t) + sizeof(uint32_t) * BASE_NUM_TWO + pubKeyLen;
    if (hapInfoSize > sizeof(caInfo->certs)) {
        tloge("buf too short, %" PUBLIC "u, %" PUBLIC "u, %" PUBLIC "u\n",
            (unsigned int)sizeof(caInfo->certs), (unsigned int)packageName.length(), (unsigned int)pubKeyLen);
        return -1;
    }

    /* packageNameLen || packageName */
    uint32_t offset = 0;
    *((uint32_t *)(caInfo->certs + offset)) = packageName.length();
    offset += sizeof(uint32_t);
    packageName.copy((char *)caInfo->certs + offset, packageName.length(), 0);
    offset += packageName.length();

    /* pubKey: pubKeyLen */
    *((uint32_t *)(caInfo->certs + offset)) = pubKeyLen + sizeof(uint32_t) * BASE_NUM_TWO;
    offset += sizeof(uint32_t);

    /* pubKey: ecc.xLen */
    *((uint32_t *)(caInfo->certs + offset)) = pubKeyLen / BASE_NUM_TWO;
    offset += sizeof(uint32_t);
    /* pubKey: ecc.x */
    if (memcpy_s(caInfo->certs + offset, sizeof(caInfo->certs) - offset,
        pubKey, pubKeyLen / BASE_NUM_TWO) != EOK) {
        tloge("copy ecc pubkey x point failed\n");
        return -1;
    }
    offset += pubKeyLen / BASE_NUM_TWO;

    /* pubKey: ecc.yLen */
    *((uint32_t *)(caInfo->certs + offset)) = pubKeyLen / BASE_NUM_TWO;
    offset += sizeof(uint32_t);
    /* pubKey: ecc.y */
    if (memcpy_s(caInfo->certs + offset, sizeof(caInfo->certs) - offset,
        pubKey + pubKeyLen / BASE_NUM_TWO, pubKeyLen / BASE_NUM_TWO) != EOK) {
        tloge("copy ecc pubkey y point failed\n");
        return -1;
    }
    offset += pubKeyLen / BASE_NUM_TWO;

    return 0;
}

static std::string GetHapAppID(void)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        tloge("GetBundleManagerProxy Failed to get system ability mgr.");
        return "";
    }
    sptr<IRemoteObject> remoteObject =
        systemAbilityManager->GetSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (remoteObject == nullptr) {
        tloge("GetBundleManagerProxy Failed to get bundle manager service.");
        return "";
    }
    sptr<AppExecFwk::IBundleMgr> bundleManager = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (bundleManager == nullptr) {
        tloge("GetBundleManagerProxy bundleManager is nullptr");
        return "";
    }
    /* userID */
    int32_t uid = IPCSkeleton::GetCallingUid();
    int32_t userId = uid / OHOS::AppExecFwk::Constants::BASE_USER_RANGE;
    tlogd("uid=%" PUBLIC "d, userId=%" PUBLIC "d\n", uid, userId);

    /* appID */
    std::string bundleName;
    bundleManager->GetNameForUid(uid, bundleName);
    return bundleManager->GetAppIdByBundleName(bundleName, userId);
}

static int32_t ConstructHapCaInfoFromToken(CaAuthInfo *caInfo)
{
    std::string appID = GetHapAppID();
    if (appID.empty()) {
        tloge("get app id failed\n");
        return -1;
    }
    tlogd("appid=%" PUBLIC "s\n", appID.c_str());
    size_t appIDLen = appID.length();
    if (appIDLen == 0 || appIDLen > sizeof(caInfo->certs)) {
        tloge("hap appid invaild, len %" PUBLIC "zu\n", appIDLen);
        return -1;
    }

    size_t posSplit = appID.find_last_of(HAP_APPID_SPLIT_CHA);
    if (posSplit == string::npos) {
        tloge("hap appid format is invaild\n");
        return -1;
    }
    string packageName = appID.substr(0, posSplit);
    string pubkeyBase64 = appID.substr(posSplit + 1, appIDLen - posSplit - 1);

    char decodedPubkey[MAX_PUBKEY_LEN] = { 0 };
    uint32_t decodedPubkeyLen = sizeof(decodedPubkey);
    int ret = Base64Decode(pubkeyBase64, (unsigned char *)decodedPubkey, &decodedPubkeyLen);
    if (ret != 0) {
        tloge("based64 pubkey decoded failed, ret %" PUBLIC "d\n", ret);
        return ret;
    }
    uint8_t unCompressedPubkeyPrefix = UNCOMPRESSED_PUBKEY_PREFIX;
    if (decodedPubkeyLen < sizeof(unCompressedPubkeyPrefix) || decodedPubkey[0] != unCompressedPubkeyPrefix) {
        tloge("invaild decoded pubkey, %" PUBLIC "u\n", decodedPubkeyLen);
        return -1;
    }
    decodedPubkeyLen = decodedPubkeyLen - sizeof(unCompressedPubkeyPrefix);

    if (decodedPubkeyLen == 0 || decodedPubkeyLen % BASE_NUM_TWO != 0) {
        tloge("invaild pub key, %" PUBLIC "u\n", decodedPubkeyLen);
        return -1;
    }

    ret = FillEccHapCaInfo(packageName, decodedPubkey + sizeof(unCompressedPubkeyPrefix), decodedPubkeyLen, caInfo);
    if (ret != 0) {
        tloge("fill ecc hap cainfo failed, ret %" PUBLIC "d\n", ret);
        return ret;
    }
    caInfo->type = APP_CA;
    return 0;
}

#define RETRY_TIMES 5
static int32_t ConstructNativeCaInfoFromToken(uint32_t tokenID, CaAuthInfo *caInfo, bool needRetry)
{
    NativeTokenInfo nativeTokenInfo;

    int32_t ret;
    int32_t retry = 0;
    bool atmReady = true;

    sptr<ISystemAbilityManager> saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (saMgr == nullptr) {
        tloge("get system ability manager failed\n");
        return -1;
    }

    if (saMgr->CheckSystemAbility(ACCESS_TOKEN_MANAGER_SERVICE_ID) == nullptr) {
        tlogi("atm service is unready.\n");
        atmReady = false;
    }

    if (!atmReady) {
        tlogi("get native callinfo info not from atm\n");
        int32_t rc = TeeGetPkgName(caInfo->pid, (char *)caInfo->certs, MAX_PATH_LENGTH);
        if (rc != 0) {
            tloge("get native ca info failed, rc %" PUBLIC "d\n", rc);
            return -1;
        }

        caInfo->type = SA_CA;
        return 0;
    }

    do {
        retry++;
        ret = AccessTokenKit::GetNativeTokenInfo(tokenID, nativeTokenInfo);
        if (ret != 0) {
            tlogi("get native token info from atm failed, retry times=%" PUBLIC "d\n", retry);
            if (needRetry) {
                sleep(1);
            }
        }
    } while (ret != 0 && retry < RETRY_TIMES && needRetry);

    if (ret != 0) {
        tloge("get native token info from atm failed, retry times=%" PUBLIC "d, ret=0x%" PUBLIC "x\n", retry, ret);
        return -1;
    }
    uint32_t processNameLen = nativeTokenInfo.processName.length();
    if (processNameLen == 0 || processNameLen > sizeof(caInfo->certs)) {
        tloge("native ca process name too long, len %" PUBLIC "u\n", processNameLen);
        return -1;
    }

    nativeTokenInfo.processName.copy((char *)caInfo->certs, processNameLen, 0);
    caInfo->type = SA_CA;
    return 0;
}

int32_t ConstructCaAuthInfo(uint32_t tokenID, CaAuthInfo *caInfo)
{
    if (caInfo == nullptr) {
        tloge("bad params, ca info is null\n");
        return -1;
    }

    ATokenTypeEnum tokenType = AccessTokenKit::GetTokenTypeFlag(tokenID);
    switch (tokenType) {
        case TOKEN_HAP:     /* for hap ca */
            tlogd("hap ca type, tokenID %" PUBLIC "u\n", tokenID);
            return ConstructHapCaInfoFromToken(caInfo);
        case TOKEN_NATIVE:  /* for native ca */
            tlogd("native ca type, tokenID %" PUBLIC "u\n", tokenID);
            return ConstructNativeCaInfoFromToken(tokenID, caInfo, false);
        case TOKEN_SHELL:   /* for native ca created by hdc */
            tlogd("shell ca type, tokenID %" PUBLIC "u\n", tokenID);
            caInfo->type = SYSTEM_CA;
            return 0;       /* cainfo: cmdline + uid */
        default:
            tloge("invaild token type %" PUBLIC "d\n", tokenType);
            return -1;
    }
}

int32_t ConstructSelfAuthInfo(CaAuthInfo *caInfo)
{
    if (caInfo == nullptr) {
        tloge("bad params, ca info is null\n");
        return -1;
    }

    caInfo->pid = getpid();
    caInfo->uid = getuid();

    uint32_t selfTokenID = OHOS::IPCSkeleton::GetSelfTokenID();
    tlogi("selfTokenID is %" PUBLIC "u\n", selfTokenID);

    return ConstructNativeCaInfoFromToken(selfTokenID, caInfo, true);
}

int32_t TEEGetNativeSACaInfo(const CaAuthInfo *caInfo, uint8_t *buf, uint32_t bufLen)
{
    if (caInfo == nullptr || buf == nullptr || bufLen == 0) {
        tloge("bad params\n");
        return -1;
    }

    /* buf format: processNameLen || processName || uidLen || uid */
    uint32_t processNameLen = strnlen((char *)caInfo->certs, sizeof(caInfo->certs));
    uint32_t uidLen = sizeof(caInfo->uid);

    uint64_t caInfoSize = sizeof(processNameLen) + processNameLen + sizeof(uidLen) + uidLen;
    if ((uint64_t)bufLen < caInfoSize) {
        tloge("buf too short, %" PUBLIC "u, %" PUBLIC "u\n", bufLen, processNameLen);
        return -1;
    }

    /* processNameLen */
    uint32_t offset = 0;
    if (memcpy_s(buf + offset, bufLen - offset, &processNameLen, sizeof(processNameLen)) != EOK) {
        tloge("copy process name len failed\n");
        return -1;
    }
    offset += sizeof(processNameLen);
    /* processName */
    if (memcpy_s(buf + offset, bufLen - offset, caInfo->certs, processNameLen) != EOK) {
        tloge("copy process name failed\n");
        return -1;
    }
    offset += processNameLen;
    /* uidLen */
    if (memcpy_s(buf + offset, bufLen - offset, &uidLen, sizeof(uidLen)) != EOK) {
        tloge("copy uid len failed\n");
        return -1;
    }
    offset += sizeof(uidLen);
    /* uid */
    if (memcpy_s(buf + offset, bufLen - offset, &(caInfo->uid), uidLen) != EOK) {
        tloge("copy uid failed\n");
        return -1;
    }

    return 0;
}

void GetCaName(char *name, int32_t len)
{
    CaAuthInfo info = { { 0 } };
    info.pid = IPCSkeleton::GetCallingPid();
    info.uid = static_cast<unsigned int>(IPCSkeleton::GetCallingUid());
    uint32_t tokenID = IPCSkeleton::GetCallingTokenID();
    ATokenTypeEnum tokenType = AccessTokenKit::GetTokenTypeFlag(tokenID);
    int ret = ConstructCaAuthInfo(tokenID, &info);
    if (ret != 0) {
        tloge("construct ca auth info failed %d\n", ret);
    }
    if (tokenType == TOKEN_SHELL) {
        ret = TeeGetPkgName(info.pid, name, len);
        if (ret != 0) {
            tloge("get ca name failed\n");
            name[0] = '\0';
        }
        return;
    } else if (tokenType == TOKEN_HAP) {
        const char *res = strchr(reinterpret_cast<const char *>(info.certs), '_');
        if (res) {
            int clen = res - reinterpret_cast<const char *>(info.certs);
            ret = memcpy_s(name, len, info.certs, clen);
            if (ret != 0) {
                tloge("get ca hap name failed\n");
                name[0] = '\0';
            }
        } else {
            tloge("find _ failed in certs %s\n", info.certs);
        }
        return;
    } else if (tokenType == TOKEN_NATIVE) {
        int clen = strnlen(reinterpret_cast<const char *>(info.certs), MAX_PATH_LENGTH - 1);
        ret = memcpy_s(name, len, info.certs, clen);
        if (ret != 0) {
            tloge("get ca native name failed\n");
            name[0] = '\0';
        }
        return;
    } else {
        tloge("invalid type %d\n", static_cast<int32_t>(tokenType));
        return;
    }
}
