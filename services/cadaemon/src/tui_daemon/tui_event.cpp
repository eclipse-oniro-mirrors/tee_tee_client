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
#include "display_info.h"
#include "cutout_info.h"
#include "call_manager_client.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"
#include "tee_file.h"
#include  "parameters.h"
#ifdef SCENE_BOARD_ENABLE
#include "display_manager_lite.h"
#include "display_lite.h"
#else
#include "display_manager.h"
#include "display.h"
#endif

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "tee_tui_daemon"

using namespace std;
using namespace OHOS::PowerMgr;
using namespace OHOS::Rosen;
using namespace OHOS::Telephony;
using namespace OHOS::system;

TUIEvent *TUIEvent::tuiInstance = nullptr;

static const uint32_t NOTCH_SIZE_MAX  = 200;
static const double INCH_CM_FACTOR    = 2.54;
static const uint32_t TUI_POLL_CANCEL = 7;
static const uint32_t TUI_POLL_NOTCH  = 24;
static const uint32_t TUI_POLL_FOLD   = 26;
static const uint32_t TUI_NEED_ROTATE = 256;

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
static std::unique_ptr<TUICallManagerCallback> mTUITelephonyCallBack_ = nullptr;
static std::shared_ptr<OHOS::Telephony::CallManagerClient> callManagerClientPtr = nullptr;

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
    int32_t fd = tee_open(TC_NS_CLIENT_DEV_NAME, O_RDWR, 0);
    if (fd < 0) {
        tloge("open tzdriver fd failed\n");
        return false;
    }
    tlogd("TUISendEventToTz get fd = %" PUBLIC "d\n", fd);

    int32_t ret = ioctl(fd, (int)TC_NS_CLIENT_IOCTL_TUI_EVENT, tuiParam);
    tee_close(&fd);
    if (ret != 0) {
        tloge("Failed to send tui event[%" PUBLIC "d] to tzdriver, ret is %" PUBLIC "d \n",
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
    tlogd("tui font hash is : %" PUBLIC "s \n", g_hashVal);

    for (i = 0, j = 0; g_hashLen > 0 && i < (g_hashLen - 1) && j < sizeof(g_ttfHash); j++) {
        g_ttfHash[j] = Ascii2Digit(g_hashVal[i++]) * HEX_BASE;
        g_ttfHash[j] += Ascii2Digit(g_hashVal[i++]);
    }

    int rc = memcpy_s(&tuiParam.value,
        sizeof(tuiParam) - sizeof(tuiParam.eventType),
        g_ttfHash, sizeof(g_ttfHash));
    if (rc == EOK) {
        if (TUISendEventToTz(&tuiParam)) {
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

bool TUIEvent::TUIGetFoldableStatus()
{
    return mTUIFoldable;
}

static uint32_t TUIGetNotch(OHOS::sptr<CutoutInfo> cutoutInfo, uint32_t displayMode)
{
    tlogi("tui get cutoutinfo--->boundingRects for notch\n");
    std::vector<OHOS::Rosen::DMRect> boundingRects = cutoutInfo->GetBoundingRects();
    if (boundingRects.empty()) {
        tlogi("get boundingRects failed\n");
        return 0;
    }
    for (uint32_t i = 0; i < boundingRects.size(); i++) {
        tlogi("tui print boundingRects[%" PUBLIC "d] info: \
posX[%" PUBLIC "d], posY[%" PUBLIC "d], width[%" PUBLIC "d], height[%" PUBLIC "d] \n",
            i, boundingRects[i].posX_, boundingRects[i].posY_,
            boundingRects[i].width_, boundingRects[i].height_);
    }
    /* calc notch, here is px, double height of the hole */
    uint32_t notch = boundingRects[0].height_ + boundingRects[0].height_;
    if (notch < 0 || notch > NOTCH_SIZE_MAX) {
        /* 200 is too large for notch, just use 0 */
        return 0;
    }
    return notch;
}

static uint32_t TUIGetDisplayMode(uint32_t foldState)
{
    if (foldState == FOLD_STATE_EXPANDED) {
        return DISPLAY_MODE_FULL;
    }

#ifdef SCENE_BOARD_ENABLE
    uint32_t displayMode = static_cast<uint32_t>(OHOS::Rosen::DisplayManagerLite::GetInstance().GetFoldDisplayMode());
#else
    uint32_t displayMode = static_cast<uint32_t>(OHOS::Rosen::DisplayManager::GetInstance().GetFoldDisplayMode());
#endif
    if (displayMode < DISPLAY_MODE_MAX) {
        return displayMode;
    }

    return DISPLAY_MODE_UNKNOWN; /* default mode */
}

bool CheckSAStarted(int32_t targetSAId)
{
    OHOS::sptr<OHOS::ISystemAbilityManager> systemAbilityManager =
        OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        tlogi("Failed to get system ability mgr\n");
        return false;
    }

    OHOS::sptr<OHOS::IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(targetSAId);
    if (!remoteObject) {
        tlogi("SA service [targetID = %" PUBLIC "d] is not exist\n", targetSAId);
        return false;
    }

    tlogd("get SA service, targetID = %" PUBLIC "d\n", targetSAId);
    return true;
}

static bool IsDisplaySAReady()
{
    int32_t retry = 0;
#ifdef SCENE_BOARD_ENABLE
    while (!CheckSAStarted(OHOS::WINDOW_MANAGER_SERVICE_ID)) {
#else
    while (!CheckSAStarted(OHOS::DISPLAY_MANAGER_SERVICE_SA_ID)) {
#endif
        if (retry++ >= RETRY_TIMES) {
            tlogi("can not get display service now\n");
            return false;
        }
        sleep(RETRY_SLEEP_TIME);
    }

    return true;
}

bool TUIEvent::TUIGetPannelInfo()
{
    if (!IsDisplaySAReady()) {
        return false;
    }

#ifdef SCENE_BOARD_ENABLE
    auto display = OHOS::Rosen::DisplayManagerLite::GetInstance().GetDefaultDisplay();
#else
    auto display = OHOS::Rosen::DisplayManager::GetInstance().GetDefaultDisplay();
#endif
    if (display == nullptr) {
        tloge("GetDefaultDisplay: failed!\n");
        return false;
    }

    OHOS::sptr<DisplayInfo> displayInfo = display->GetDisplayInfo();
    if (displayInfo != nullptr) {
        tlogi("get xdpi %" PUBLIC "f, ydpi %" PUBLIC "f, displaystate %" PUBLIC "u, DPI %" PUBLIC "d \n",
            displayInfo->GetXDpi(), displayInfo->GetYDpi(),
            (uint32_t)displayInfo->GetDisplayState(), displayInfo->GetDpi());
    } else {
        tloge("get displayInfo failed\n");
        return false;
    }

    TUIGetFoldable();

    mTUIPanelInfo.width = display->GetWidth();
    mTUIPanelInfo.height = display->GetHeight();

    if (displayInfo->GetXDpi() != 0 && displayInfo->GetYDpi() != 0) {
        mTUIPanelInfo.phyWidth = mTUIPanelInfo.width * INCH_CM_FACTOR / displayInfo->GetXDpi();
        mTUIPanelInfo.phyHeight = mTUIPanelInfo.height * INCH_CM_FACTOR / displayInfo->GetYDpi();
    }

    OHOS::sptr<CutoutInfo> cutoutInfo = display->GetCutoutInfo();
    if (cutoutInfo == nullptr) {
        tloge("get cutoutinfo failed\n");
    } else {
        mTUIPanelInfo.notch = TUIGetNotch(cutoutInfo, mTUIPanelInfo.displayMode);
    }

    tlogi("tui panelinfo: w %" PUBLIC "d, h %" PUBLIC "d, fold %" PUBLIC "u, "
        "displayMode %" PUBLIC "u, notch %" PUBLIC "u\n",
        mTUIPanelInfo.width, mTUIPanelInfo.height, mTUIPanelInfo.foldState,
        mTUIPanelInfo.displayMode, mTUIPanelInfo.notch);

    return true;
}

void TUIEvent::TUIGetFoldable()
{
#ifdef SCENE_BOARD_ENABLE
    mTUIFoldable = OHOS::Rosen::DisplayManagerLite::GetInstance().IsFoldable();
#else
    mTUIFoldable = OHOS::Rosen::DisplayManager::GetInstance().IsFoldable();
#endif
    tlogi("TuiDaemonInit mTUIFoldable %" PUBLIC "d\n", mTUIFoldable);
    if (mTUIFoldable) {
        tlogi("tui get fold state\n");
    #ifdef SCENE_BOARD_ENABLE
        mTUIPanelInfo.foldState = static_cast<uint32_t>(OHOS::Rosen::DisplayManagerLite::GetInstance().GetFoldStatus());
    #else
        mTUIPanelInfo.foldState = static_cast<uint32_t>(OHOS::Rosen::DisplayManager::GetInstance().GetFoldStatus());
    #endif
        if (mTUIPanelInfo.foldState > FOLD_STATE_HALF_FOLDED) {
            mTUIPanelInfo.foldState = FOLD_STATE_UNKNOWN; /* default state */
        }
    } else {
        mTUIPanelInfo.foldState = FOLD_STATE_UNKNOWN;
    }

    mTUIPanelInfo.displayMode = TUIGetDisplayMode(mTUIPanelInfo.foldState);

    std::string buildProduct = OHOS::system::GetParameter("const.build.product", "0");
    if (buildProduct == "DEL") {
        mTUIPanelInfo.displayMode = TUI_NEED_ROTATE;
    }

    if (buildProduct == "VDE") {
        if (mTUIPanelInfo.foldState == FOLD_STATE_EXPANDED || mTUIPanelInfo.foldState == FOLD_STATE_HALF_FOLDED) {
            mTUIPanelInfo.foldState = FOLD_STATE_UNKNOWN;
        }
    }

    std::string foldScreenType = OHOS::system::GetParameter("const.window.foldscreen.type", "0");
    // trifold phone
    if (foldScreenType == "6,1,0,0") {
        mTUIPanelInfo.foldState += TUI_NEED_ROTATE;
        mTUIPanelInfo.displayMode = TUI_NEED_ROTATE;
    }

    if (mTUIPanelInfo.foldState == FOLD_STATE_EXPANDED || mTUIPanelInfo.foldState == FOLD_STATE_HALF_FOLDED) {
        mTUIPanelInfo.foldState += TUI_NEED_ROTATE;
    }

    return;
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
    mRunningLock_ = nullptr;

    mTUIPanelInfo = { 0 };
    mTUIStatus = false;
    mTUIFoldable = false;

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
        tloge("tui send cmd failed\n");
        return false;
    }

    return true;
}

void TUIEvent::TUIDealWithEvent(bool state)
{
    if (state == false) {
        /* not need send cmd to tzdriver */
        TUIReleaseRunningLock();
        TUISetStatus(false);
        return;
    }

    TUIGetRunningLock();
    TUIGetPannelInfo();
    TUISetStatus(true);
    TUISendCmd(TUI_POLL_FOLD);
}

void TUIDisplayListener::OnFoldStatusChanged(OHOS::Rosen::FoldStatus foldState)
{
    if (foldState != OHOS::Rosen::FoldStatus::EXPAND && foldState != OHOS::Rosen::FoldStatus::FOLDED) {
        tloge("foldState = %" PUBLIC "u invalid\n", static_cast<uint32_t>(foldState));
        return;
    }

    /* if foldState changed, should:
     * 1. get pannelinfo,
     * 2. send infos to teeos,
     * 3. cancel current running proc
     */
    auto tempTUIInstance = TUIEvent::GetInstance();
    if (tempTUIInstance == nullptr) {
        return;
    }
    tlogi("get TUIStatus is %" PUBLIC "x\n", tempTUIInstance->TUIGetStatus());
    if (tempTUIInstance->TUIGetPannelInfo()) {
        (void)tempTUIInstance->TUISendCmd(TUI_POLL_FOLD);  /* EVENT TUI_POLL_FOLD */
    }
    if (tempTUIInstance->TUIGetStatus()) {
        tlogi("foldState changed, need cancel TUI proc\n");
        (void)tempTUIInstance->TUISendCmd(TUI_POLL_CANCEL); /* EVENT Exit */
    }
}

int32_t TUICallManagerCallback::OnCallDetailsChange(const OHOS::Telephony::CallAttributeInfo &info)
{
    tlogd("----------OnCallDetailsChange--------\n");
    tlogd("callId: %" PUBLIC "x\n", info.callId);
    tlogd("callType: %" PUBLIC "x\n", (int32_t)info.callType);
    tlogd("callState: %" PUBLIC "x\n", (int32_t)info.callState);
    tlogd("conferenceState: %" PUBLIC "x\n", (int32_t)info.conferenceState);
    tlogd("accountNumber: %" PUBLIC "s\n", info.accountNumber);

    if (info.callState == OHOS::Telephony::TelCallState::CALL_STATUS_INCOMING) {
        auto tempTUIInstance = TUIEvent::GetInstance();
        if (tempTUIInstance->TUIGetStatus()) {
            tlogi("new call state CALL_STATUS_INCOMING, need send cmd to teeos to cancel TUI proc\n");
            tempTUIInstance->TUISetStatus(false); /* change tuiStatus to false */
            (void)tempTUIInstance->TUISendCmd(TUI_POLL_CANCEL);  /* EVENT Exit */
        }
        tlogd("tui get new call state CALL_STATUS_INCOMING\n");
    }
    return 0;
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
        tloge("regist telephony callback failed ret = 0x%" PUBLIC "x\n", ret);
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

    if (!IsDisplaySAReady()) {
        return;
    }

    if (mTUIDisplayListener_ == nullptr) {
        mTUIDisplayListener_ = new (std::nothrow) TUIDisplayListener();
        if (mTUIDisplayListener_ == nullptr) {
            tloge("create listener obj failed\n");
            return;
        }
    }
#ifdef SCENE_BOARD_ENABLE
    OHOS::Rosen::DisplayManagerLite &dmPtr = (OHOS::Rosen::DisplayManagerLite::GetInstance());
#else
    OHOS::Rosen::DisplayManager &dmPtr = (OHOS::Rosen::DisplayManager::GetInstance());
#endif
    int32_t result = (int32_t)dmPtr.RegisterFoldStatusListener(mTUIDisplayListener_);
    if (result == TEEC_SUCCESS) {
        g_tuiDisplayListenerRegisted = true;
        tlogi("regist display listener done\n");
    } else {
        tloge("regist display listener failed\n");
    }
}

void TUIDaemon::TuiDaemonInit(bool onlyConfigRes)
{
    TUISaveTTFHash();
    auto tuiEvent = TUIEvent::GetInstance();
    tuiEvent->TuiEventInit();

    if (!onlyConfigRes) {
        TuiRegisteCallBack();
        TuiRegisteDisplayListener();
    }

    tlogi("TUIDaemon init ok\n");
}

TUIDaemon::~TUIDaemon()
{
    if (mTUIDisplayListener_ != nullptr) {
#ifdef SCENE_BOARD_ENABLE
        OHOS::Rosen::DisplayManagerLite::GetInstance().UnregisterFoldStatusListener(mTUIDisplayListener_);
#else
        OHOS::Rosen::DisplayManager::GetInstance().UnregisterFoldStatusListener(mTUIDisplayListener_);
#endif
        mTUIDisplayListener_ = nullptr;
    }

    if (g_tuiCallBackRegisted) {
        OHOS::DelayedSingleton<OHOS::Telephony::CallManagerClient>::GetInstance()->UnRegisterCallBack();
        g_tuiCallBackRegisted = false;
    }

    tlogi("TUIDaemon released\n");
}
