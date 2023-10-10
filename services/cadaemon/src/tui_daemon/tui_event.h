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

#ifndef TUI_EVENT_H
#define TUI_EVENT_H

#include <cstdint>
#include <cstdio>

#include "running_lock.h"
#include "display_manager.h"
#include "pac_map.h"
#include "call_manager_callback.h"


#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "tee_tui_daemon"

typedef struct {
    uint32_t eventType; /* Tui event type */
    uint32_t value;   /* return value, is keycode if tui event is getKeycode */
    uint32_t notch;   /* notch size of phone */
    uint32_t width;   /* width of foldable screen : cm */
    uint32_t height;  /* height of foldable screen : cm */
    uint32_t foldState;    /* state of foldable screen */
    uint32_t displayState; /* one state of folded state */
    uint32_t phyWidth;     /* real width of the mobile : px */
    uint32_t phyHeight;    /* real height of the mobile : px */
} TuiParameter;

class TUIEvent {
private:
    TUIEvent() = default;
    ~TUIEvent() = default;

    static TUIEvent *tuiInstance;
    std::shared_ptr<OHOS::PowerMgr::RunningLock> mRunningLock_;
    TuiParameter mTUIPanelInfo;
    bool mTUIStatus;
public:
    static TUIEvent *GetInstance()
    {
        if (tuiInstance == nullptr) {
            tuiInstance = new TUIEvent();
        }
        return tuiInstance;
    }

    void TuiEventInit();
    void TUIGetRunningLock();
    void TUIReleaseRunningLock();
    int32_t TUIGetPannelInfo();
    void TUISetStatus(bool status);
    bool TUIGetStatus();
    int32_t TUIDealWithEvent(bool state);
    bool TUISendCmd(uint32_t tuiEvent);
};

class TUIDisplayListener : public OHOS::Rosen::DisplayManager::IDisplayListener {
public:
    TUIDisplayListener() = default;
    ~TUIDisplayListener() = default;
    void OnCreate(OHOS::Rosen::DisplayId dId) override {}
    void OnDestroy(OHOS::Rosen::DisplayId dId) override {}
    void OnChange(OHOS::Rosen::DisplayId dId) override;
};

class TUICallManagerCallback : public OHOS::Telephony::CallManagerCallback {
public:
    TUICallManagerCallback() = default;
    ~TUICallManagerCallback() = default;
    int32_t OnCallDetailsChange(const OHOS::Telephony::CallAttributeInfo &info) override;
    int32_t OnCallEventChange(const OHOS::Telephony::CallEventInfo &info) override { return 0; }
    int32_t OnCallDisconnectedCause(const OHOS::Telephony::DisconnectedDetails &details) override { return 0; }
    int32_t OnReportAsyncResults(OHOS::Telephony::CallResultReportId reportId,
        OHOS::AppExecFwk::PacMap &resultInfo) override { return 0; }
    int32_t OnOttCallRequest(OHOS::Telephony::OttCallRequestId requestId,
        OHOS::AppExecFwk::PacMap &info) override { return 0; }
    int32_t OnReportMmiCodeResult(const OHOS::Telephony::MmiCodeInfo &info) override { return 0; }
    int32_t OnReportAudioDeviceChange(const OHOS::Telephony::AudioDeviceInfo &info) override { return 0; }
    int32_t OnReportPostDialDelay(const std::string &str) override { return 0; }
};

class TUIDaemon {
public:
    TUIDaemon() = default;
    ~TUIDaemon();
    void TuiDaemonInit();
    OHOS::sptr<TUIDisplayListener> mTUIDisplayListener_ = nullptr;
private:
    void TuiRegisteCallBack();
    void TuiRegisteDisplayListener();
    bool CheckSAStarted(int32_t targetSAId);
};
#endif