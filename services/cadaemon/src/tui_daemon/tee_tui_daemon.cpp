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

#include <cstdint>
#include <cstdio>
#include <ctime>
#include <securec.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include "tee_client_type.h"
#include "tee_log.h"
#include "tc_ns_client.h"
#include "tui_event.h"

#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "tee_tui_daemon"

using namespace std;

static TUIEvent *g_tuiEventInstance = nullptr;
static TUIDaemon *g_tuiDaemon = nullptr;
static bool g_tuiDaemonInit = false;
static bool g_tuiFoldable = false;

#ifdef __cplusplus
extern "C" {
#endif

static const uint32_t TUI_POLL_FOLD   = 26;

static void TuiDaemonClear();

static bool TuiDaemonInit(bool onlyConfigRes)
{
    if (g_tuiDaemonInit) {
        return true;
    }

    g_tuiDaemon = new TUIDaemon();
    if (g_tuiDaemon == nullptr) {
        return false;
    }

    g_tuiDaemon->TuiDaemonInit(onlyConfigRes);
    g_tuiEventInstance = TUIEvent::GetInstance();
    if (!g_tuiEventInstance->TUIGetPannelInfo()) {
        TuiDaemonClear();
        return false;
    }

    g_tuiFoldable = g_tuiEventInstance->TUIGetFoldableStatus();
    tlogi("TuiDaemonInit g_tuiFoldable %" PUBLIC "d\n", g_tuiFoldable);
    if (!g_tuiEventInstance->TUISendCmd(TUI_POLL_FOLD)) {
        TuiDaemonClear();
        return false;
    }

    g_tuiDaemonInit = true;
    return g_tuiDaemonInit;
}

static void TuiDaemonClear()
{
    if (g_tuiDaemon != nullptr) {
        delete g_tuiDaemon;
        g_tuiDaemon = nullptr;
    }

    g_tuiDaemonInit = false;
}

bool TeeTuiDaemonWork(int tuiState)
{
    if (tuiState <= TUI_STATE_INVALID || tuiState >= TUI_STATE_MAX) {
        tlogi("invalid tui cmd\n");
        return false;
    }

    bool onlyConfigRes = false;
    if (tuiState == TUI_STATE_INIT) {
        onlyConfigRes = true;
    }

    if (!TuiDaemonInit(onlyConfigRes)) {
        return false;
    }

    if (tuiState == TUI_STATE_TUI_START) {
        tlogi("send true state to frame 2\n");
        g_tuiEventInstance->TUIDealWithEvent(true);
    } else if (tuiState == TUI_STATE_TUI_END) {
        tlogi("send false state to frame 2\n");
        g_tuiEventInstance->TUIDealWithEvent(false);
        TuiDaemonClear();
    }

    return true;
}

bool TeeTuiIsFoldable(void)
{
    return g_tuiFoldable;
}

#ifdef __cplusplus
}
#endif
