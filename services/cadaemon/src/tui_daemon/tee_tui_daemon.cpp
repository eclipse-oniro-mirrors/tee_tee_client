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

TUIEvent *g_tuiEventInstance = nullptr;
TUIDaemon *g_tuiDaemon = nullptr;

#ifdef __cplusplus
extern "C" {
#endif

static const int32_t EVENT_PARAMS_LEN = 16;
static const int32_t PARAMS_INPUT_LEN = 10;
static const uint32_t TUI_POLL_FOLD   = 26;
static const uint32_t SLEEP_TIME = 1;
static const int32_t RETRY_TIMES = 20;
static FILE *g_mTuiFp = nullptr;

static FILE *GetTuiDevFd()
{
    FILE *tuiFp = nullptr;
    int32_t retryTimes = 0;

    while (tuiFp == nullptr) {
        tuiFp = fopen(TUI_LISTEN_PATH, "rb");
        if (tuiFp == nullptr) {
            retryTimes++;
            sleep(SLEEP_TIME);
            if (retryTimes > RETRY_TIMES) {
                tloge("can not open %{public}s , %{public}d", TUI_LISTEN_PATH, errno);
                return nullptr;
            }
        }
    }
    return tuiFp;
}

static int32_t GetEvent(char *eventParam, int *paramLen)
{
    int32_t readSize = 0;

    if (g_mTuiFp == nullptr) {
        g_mTuiFp = GetTuiDevFd();
        if (g_mTuiFp == nullptr) {
            tloge("get TuiFd failed\n");
            return -1;
        }
    }

    fseek(g_mTuiFp, 0, SEEK_SET);
    tlogi("Tui SEEK_SET ok\n");
    readSize = fread(eventParam, 1, *paramLen, g_mTuiFp);
    if (readSize <= 0) {
        tloge("TUI read state fail %{public}d, len=%{public}d\n", ferror(g_mTuiFp), readSize);
        fclose(g_mTuiFp);
        g_mTuiFp = nullptr;
        return -1;
    } else {
        *(eventParam + readSize) = '\0';
        tlogi("get c_state len is %{public}d\n", readSize);
    }

    *paramLen = readSize;

    return 0;
}

static void HandleEvent(const char *eventParam, int32_t paramLen)
{
    const char *str = eventParam;

    if (strncmp(str, "unused", sizeof("unused")) == 0) {
        tlogi("send false state to frame \n");
        g_tuiEventInstance->TUIDealWithEvent(false);
    } else if (strncmp(str, "config", sizeof("config")) == 0) {
        tlogi("send true state to frame \n");
        g_tuiEventInstance->TUIDealWithEvent(true);
    } else {
        tlogi("do not need send data\n");
    }

    return;
}

static void ThreadInit()
{
    g_tuiDaemon = new TUIDaemon();
    g_tuiDaemon->TuiDaemonInit();
    g_tuiEventInstance = TUIEvent::GetInstance();
    g_tuiEventInstance->TUIGetPannelInfo();
    g_tuiEventInstance->TUISendCmd(TUI_POLL_FOLD);
}

static void ThreadClear()
{
    if (g_mTuiFp != nullptr) {
        fclose(g_mTuiFp);
        g_mTuiFp = nullptr;
    }

    if (g_tuiDaemon != nullptr) {
        delete g_tuiDaemon;
        g_tuiDaemon = nullptr;
    }
}

static void TuiThreadLoop()
{
    tlogi("Tui Thread Loop Start\n");
    g_mTuiFp = GetTuiDevFd();
    if (g_mTuiFp == nullptr) {
        tloge("failed to get c_state, stop ThreadLoop\n");
        return;
    }

    ThreadInit();

    do {
        char eventParam[EVENT_PARAMS_LEN];
        int32_t paramLen = PARAMS_INPUT_LEN;
        int32_t ret = GetEvent(eventParam, &paramLen);
        if (ret == 0) {
            HandleEvent(eventParam, paramLen);
        } else {
            tloge("get event failed, something wrong\n");
            break;
        }
    } while (true);
    tlogi("Tui Thread Loop stop\n");
    ThreadClear();
}

void TeeTuiThreadWork(void)
{
    TuiThreadLoop();
    return;
}

#ifdef __cplusplus
}
#endif