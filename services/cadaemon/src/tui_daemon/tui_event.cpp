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

#include "tui_event.h"
#include <cctype>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <cstdio>
#include <memory>
#include <fcntl.h>
#include <unistd.h>
#include <securec.h>
#include <securectype.h>
#include <sys/ioctl.h>

#include "tee_log.h"
#include "tc_ns_client.h"
#include "power_mgr_client.h"
#include "display_manager.h"
#include "display.h"
#include "display_info.h"
#include "call_manager_client.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "tee_tui_daemon"

using namespace std;
using namespace OHOS::PowerMgr;
using namespace OHOS::Rosen;
using namespace OHOS::Telephony;

TUIEvent *TUIEvent::tuiInstance = nullptr;

static const double INCH_CM_FACTOR    = 2.54;
static const uint32_t TUI_POLL_CANCEL = 7;
static const uint32_t TUI_POLL_NOTCH  = 24;
static const uint32_t TUI_POLL_FOLD   = 26;

static const uint8_t TTF_HASH_SIZE   = 32;
static const uint8_t TTF_STRING_SIZE = 64;
static const uint8_t HEX_BASE        = 16;
static const uint8_t ASCII_DIGIT_GAP = 10;
static uint8_t g_ttfHash[TTF_HASH_SIZE];

static char g_hashVal[TTF_STRING_SIZE + 1] = {0};
static uint32_t g_hashLen = 0;
static bool g_tuiSendHashSuccess = false;
static bool g_tuiDisplayListenerRegisted = false;
static bool g_tuiCallBackRegisted = false;
static const int32_t RETRY_TIMES = 20;
static const uint32_t RETRY_SLEEP_TIME = 2;
std::unique_ptr<TUICallManagerCallback> mTUITelephonyCallBack_ = nullptr;
std::shared_ptr<OHOS::Telephony::CallManagerClient> callManagerClientPtr = nullptr;

static void TUISaveTTFHash(void)
{
#ifndef FONT_HASH_VAL
    tlogi("tui font hash not defined\n");
#else
    const char *hashStr = FONT_HASH_VAL;
    if (hashStr == NULL) {
        tloge("get hashstr error\n");
        return;
    }

    g_hashLen = (uint32_t)strlen(hashStr);
    if (g_hashLen != TTF_STRING_SIZE) {
        tloge("ttf hash invalid\n");
        g_hashLen = 0;
        return;
    }
    if (memcpy_s(g_hashVal, TTF_STRING_SIZE, hashStr, g_hashLen) != EOK) {
        tloge("copy hash string failed\n");
        g_hashLen = 0;
        return;
    }
#endif
    return;
}

static uint8_t Ascii2Digit(char a)
{
    uint8_t hex = 0;

    if ((a >= '0') && (a <= '9')) {
        hex = a - '0';
    } else if ((a >= 'a') && (a <= 'f')) {
        hex = (a - 'a') + ASCII_DIGIT_GAP;
    } else if ((a >= 'A') && (a <= 'F')) {
        hex = (a - 'A') + ASCII_DIGIT_GAP;
    }

    return hex;
}

static bool TUISendEventToTz(TuiParameter *tuiParam)
{
    int32_t fd = open(TC_NS_CLIENT_DEV_NAME, O_RDWR);
    if (fd < 0) {
        tloge("open tzdriver fd failed\n");
        return false;
    }
    tlogd("TUISendEventToTz get fd = %{public}d\n", fd);

    int32_t ret = ioctl(fd, (int)TC_NS_CLIENT_IOCTL_TUI_EVENT, tuiParam);
    (void)close(fd);
    if (ret != 0) {
        tloge("Failed to send tui event[%{public}d] to tzdriver, ret is %{public}d \n",
            tuiParam->eventType, ret);
        return false;
    }
    return true;
}

static void TUISendTTFHashToTeeos(void)
{
    uint32_t i, j;
    TuiParameter tuiParam = {.eventType = TUI_POLL_NOTCH};

    if (g_tuiSendHashSuccess) {
        return;
    }

    if (g_hashLen != TTF_STRING_SIZE) {
        tloge("tui font hash len invalid\n");
        g_hashLen = 0;
        return;
    }
    tlogd("tui font hash is : %{public}s \n", g_hashVal);

    for (i = 0, j = 0; g_hashLen > 0 && i < (g_hashLen - 1) && j < sizeof(g_ttfHash); j++) {
        g_ttfHash[j] = Ascii2Digit(g_hashVal[i++]) * HEX_BASE;
        g_ttfHash[j] += Ascii2Digit(g_hashVal[i++]);
    }

    int rc = memcpy_s(&tuiParam.value,
        sizeof(tuiParam) - sizeof(tuiParam.eventType),
        g_ttfHash, sizeof(g_ttfHash));
    if (rc == EOK) {
        if (TUISendEventToTz(&tuiParam) == true) {
            g_tuiSendHashSuccess = true;
        } else {
            tloge("send notch msg failed\n");
        }
    } else {
        tloge("memcpy tui font hash failed");
    }
}

void TUIEvent::TUISetStatus(bool status)
{
    mTUIStatus = status;
}

bool TUIEvent::TUIGetStatus()
{
    return mTUIStatus;
}

int TUIEvent::TUIGetPannelInfo()
{
    auto display = OHOS::Rosen::DisplayManager::GetInstance().GetDefaultDisplay();
    if (display == nullptr) {
        tloge("GetDefaultDisplay: failed!\n");
        return -1;
    }
    tlogi("GetDefaultDisplay: w %{public}d, h %{public}d, fps %{public}u\n",
        display->GetWidth(),
        display->GetHeight(),
        display->GetRefreshRate());

    OHOS::sptr<DisplayInfo> displayInfo = display->GetDisplayInfo();
    if (displayInfo != nullptr) {
        float xDpi = displayInfo->GetXDpi();
        float yDpi = displayInfo->GetYDpi();
        uint32_t displayState = (uint32_t)displayInfo->GetDisplayState();
        tlogi("get xdpi %{public}f, ydpi %{public}f, displaystate %{public}u \n", xDpi, yDpi, displayState);
    } else {
        tloge("get displayInfo failed\n");
        return -1;
    }

    mTUIPanelInfo.foldState = 0;  // FOLD_STATE_UNKNOWN
    mTUIPanelInfo.displayState = (uint32_t)displayInfo->GetDisplayState();
    mTUIPanelInfo.notch = 0;
    mTUIPanelInfo.width = display->GetWidth();
    mTUIPanelInfo.height = display->GetHeight();
    if (displayInfo->GetXDpi() != 0 && displayInfo->GetYDpi() != 0) {
        mTUIPanelInfo.phyWidth = mTUIPanelInfo.width * INCH_CM_FACTOR / displayInfo->GetXDpi();
        mTUIPanelInfo.phyHeight = mTUIPanelInfo.height * INCH_CM_FACTOR / displayInfo->GetYDpi();
    }

    return 0;
}

void TUIEvent::TUIGetRunningLock()
{
    if (mRunningLock_ == nullptr) {
        auto &powerMgrClient = OHOS::PowerMgr::PowerMgrClient::GetInstance();
        mRunningLock_ = powerMgrClient.CreateRunningLock("TuiDaemonRunningLock",
            OHOS::PowerMgr::RunningLockType::RUNNINGLOCK_SCREEN);
    }

    if (mRunningLock_ != nullptr) {
        mRunningLock_->Lock();
        tlogi("TUI Get RunningLock\n");
    }
    return;
}

void TUIEvent::TUIReleaseRunningLock()
{
    if (mRunningLock_ != nullptr) {
        mRunningLock_->UnLock();
    }

    tlogi("TUI Release RunningLock\n");
    return;
}

void TUIEvent::TuiEventInit()
{
    auto &powerMgrClient = OHOS::PowerMgr::PowerMgrClient::GetInstance();
    mRunningLock_ = powerMgrClient.CreateRunningLock("TuiDaemonRunningLock",
        OHOS::PowerMgr::RunningLockType::RUNNINGLOCK_SCREEN);

    mTUIPanelInfo = { 0 };
    mTUIStatus = false;

    TUISendTTFHashToTeeos();

    return;
}

bool TUIEvent::TUISendCmd(uint32_t tuiEvent)
{
    TuiParameter tuiParam = {0};

    if (tuiEvent == TUI_POLL_CANCEL) {
        tuiParam.eventType = TUI_POLL_CANCEL;
        tuiParam.value = 0;
    } else {
        (void)memcpy_s(&tuiParam, sizeof(tuiParam), &mTUIPanelInfo, sizeof(mTUIPanelInfo));
        tuiParam.eventType = TUI_POLL_FOLD;
        tuiParam.value = 0;
    }

    /* if not send hash success, try again */
    TUISendTTFHashToTeeos();

    if (TUISendEventToTz(&tuiParam) == false) {
        return -1;
    }

    return 0;
}

int32_t TUIEvent::TUIDealWithEvent(bool state)
{
    if (state == false) {
        /* not need send cmd to tzdriver */
        TUIReleaseRunningLock();
        TUISetStatus(false);
        return 0;
    }

    TUIGetRunningLock();
    TUIGetPannelInfo();
    TUISetStatus(true);
    return TUISendCmd(TUI_POLL_FOLD);
}

void TUIDisplayListener::OnChange(OHOS::Rosen::DisplayId dId)
{
    auto tempTUIInstance = TUIEvent::GetInstance();
    if (tempTUIInstance == nullptr) {
        return;
    }

    if (dId < 0) {
        tloge("displayId invalid\n");
        return;
    }

    tlogi("get TUIStatus is %{public}x\n", tempTUIInstance->TUIGetStatus());
    /* if pannelinfo changed, should:
     * 1. get pannelinfo,
     * 2. send infos to teeos,
     * 3. cancel current running proc
     */
    tempTUIInstance->TUIGetPannelInfo();
    tempTUIInstance->TUISendCmd(TUI_POLL_FOLD);  /* EVENT TUI_POLL_FOLD */
    if (tempTUIInstance->TUIGetStatus() == true) {
        tlogi("display state changed, need cancel TUI proc\n");
        /* DO NOT change tuiStatus to false, and do not know why */
        tempTUIInstance->TUISendCmd(TUI_POLL_CANCEL); /* EVENT Exit */
    }
}

int32_t TUICallManagerCallback::OnCallDetailsChange(const OHOS::Telephony::CallAttributeInfo &info)
{
    tlogd("----------OnCallDetailsChange--------\n");
    tlogd("callId: %{public}x\n", info.callId);
    tlogd("callType: %{public}x\n", (int32_t)info.callType);
    tlogd("callState: %{public}x\n", (int32_t)info.callState);
    tlogd("conferenceState: %{public}x\n", (int32_t)info.conferenceState);
    tlogd("accountNumber: %{public}s\n", info.accountNumber);

    if (info.callState == OHOS::Telephony::TelCallState::CALL_STATUS_INCOMING) {
        /* call is incoming */
        auto tempTUIInstance = TUIEvent::GetInstance();
        if (tempTUIInstance->TUIGetStatus() == true) {
            tlogi("new call state CALL_STATUS_INCOMING, need send cmd to teeos to cancel TUI proc\n");
            tempTUIInstance->TUISetStatus(false); /* change tuiStatus to false */
            tempTUIInstance->TUISendCmd(TUI_POLL_CANCEL);  /* EVENT Exit */
        }
        tlogd("tui get new call state CALL_STATUS_INCOMING\n");
    }
    return 0;
}

bool TUIDaemon::CheckSAStarted(int32_t targetSAId)
{
    OHOS::sptr<OHOS::ISystemAbilityManager> systemAbilityManager =
        OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        tlogi("Failed to get system ability mgr\n");
        return false;
    }

    OHOS::sptr<OHOS::IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(targetSAId);
    if (!remoteObject) {
        tlogi("SA service [targetID = %{public}d] is not exist\n", targetSAId);
        return false;
    }

    tlogd("get SA service, targetID = %{public}d\n", targetSAId);
    return true;
}

void TUIDaemon::TuiRegisteCallBack()
{
    if (g_tuiCallBackRegisted) {
        return;
    }

    int32_t retry = 0;
    while (CheckSAStarted(OHOS::TELEPHONY_CALL_MANAGER_SYS_ABILITY_ID) == false) {
        sleep(RETRY_SLEEP_TIME);
        retry++;
        if (retry >= RETRY_TIMES) {
            tlogi("can not get telephony service now\n");
            return;
        }
    }

    if (mTUITelephonyCallBack_ == nullptr) {
        mTUITelephonyCallBack_ = std::make_unique<TUICallManagerCallback>();
        if (mTUITelephonyCallBack_ == nullptr) {
            tloge("init callback instance failed\n");
            return;
        }
    }

    if (callManagerClientPtr == nullptr) {
        callManagerClientPtr = OHOS::DelayedSingleton<OHOS::Telephony::CallManagerClient>::GetInstance();
        if (callManagerClientPtr == nullptr) {
            tloge("get callManagerClientPtr failed\n");
            return;
        }
    }

    tlogi("callback get instance finish\n");
    callManagerClientPtr->Init(OHOS::TELEPHONY_CALL_MANAGER_SYS_ABILITY_ID);
    tlogi("callback init finish\n");
    int32_t ret = callManagerClientPtr->RegisterCallBack(std::move(mTUITelephonyCallBack_));
    if (ret != TEEC_SUCCESS) {
        tloge("regist telephony callback failed ret = 0x%{public}x\n", ret);
        callManagerClientPtr->UnInit();
    } else {
        g_tuiCallBackRegisted = true;
        tlogi("regist telephony callback done\n");
    }
}

void TUIDaemon::TuiRegisteDisplayListener()
{
    if (g_tuiDisplayListenerRegisted) {
        return;
    }

    int32_t retry = 0;
    while (CheckSAStarted(OHOS::DISPLAY_MANAGER_SERVICE_SA_ID) == false) {
        sleep(RETRY_SLEEP_TIME);
        retry++;
        if (retry >= RETRY_TIMES) {
            tlogi("can not get display service now\n");
            return;
        }
    }

    if (mTUIDisplayListener_ == nullptr) {
        mTUIDisplayListener_ = new TUIDisplayListener();
        if (mTUIDisplayListener_ == nullptr) {
            tloge("create listener obj failed\n");
            return;
        }
    }

    OHOS::Rosen::DisplayManager& dmPtr = (OHOS::Rosen::DisplayManager::GetInstance());
    int32_t result = (int32_t)dmPtr.RegisterDisplayListener(mTUIDisplayListener_);
    if (result == TEEC_SUCCESS) {
        g_tuiDisplayListenerRegisted = true;
        tlogi("regist display listener done\n");
    } else {
        tloge("regist display listener failed\n");
    }
}

void TUIDaemon::TuiDaemonInit()
{
    TUISaveTTFHash();
    auto tuiEvent = TUIEvent::GetInstance();
    tuiEvent->TuiEventInit();

    TuiRegisteCallBack();
    TuiRegisteDisplayListener();

    tlogi("TUIDaemon init ok\n");
}

TUIDaemon::~TUIDaemon()
{
    if (mTUIDisplayListener_ != nullptr) {
        OHOS::Rosen::DisplayManager::GetInstance().UnregisterDisplayListener(mTUIDisplayListener_);
        mTUIDisplayListener_ = nullptr;
    }

    OHOS::DelayedSingleton<OHOS::Telephony::CallManagerClient>::GetInstance()->UnInit();

    tlogi("TUIDaemon released\n");
}