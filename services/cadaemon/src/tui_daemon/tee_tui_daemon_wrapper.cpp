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
#include <dlfcn.h>
#include "tee_client_type.h"
#include "tee_log.h"
#include "tc_ns_client.h"
#include "tui_file.h"
#include "tui_threadwork.h"
#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "tee_tui_daemon"

#ifdef __cplusplus
extern "C" {
#endif

static const int32_t EVENT_PARAMS_LEN = 16;
static const int32_t PARAMS_INPUT_LEN = 10;
static const uint32_t SLEEP_TIME = 1;
static const int32_t RETRY_TIMES = 20;
static const uint32_t WAIT_BEFORE_DLCLOSE = 2;
static FILE *g_mTuiFp = nullptr;

enum {
    TUI_DAEMON_TUI_INIT = 1,
    TUI_DAEMON_TUI_START = 2,
    TUI_DAEMON_TUI_END = 3
};

static FILE *GetTuiDevFd()
{
    FILE *tuiFp = nullptr;
    int32_t retryTimes = 0;
    while (tuiFp == nullptr) {
        tuiFp = GetTuiCStateFp(TUI_LISTEN_PATH, "rb");
        if (tuiFp == nullptr) {
            retryTimes++;
            sleep(SLEEP_TIME);
            if (retryTimes > RETRY_TIMES) {
                tloge("can not open %" PUBLIC "s, %" PUBLIC "d", TUI_LISTEN_PATH, errno);
                return nullptr;
            }
        }
    }
    return tuiFp;
}

int32_t GetEvent(char *eventParam, int *paramLen)
{
    if (eventParam == nullptr || paramLen == nullptr) {
        return -1;
    }

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
    readSize = GetEventParamFromTui(eventParam, 1, *paramLen, g_mTuiFp);
    if (readSize <= 0) {
        tloge("TUI read state fail %" PUBLIC "d, len=%" PUBLIC "d\n", ferror(g_mTuiFp), readSize);
        return -1;
    } else {
        *(eventParam + readSize) = '\0';
        tlogi("get c_state len is %" PUBLIC "d\n", readSize);
    }

    *paramLen = readSize;

    return 0;
}

static void *g_dlHandle = nullptr;
bool (*g_tuiDaemonFunc)(int) = nullptr;
bool (*g_tuiIsFoldableFunc)() = nullptr;
static bool TuiDaemonInit(void)
{
    tlogi("tui daemon init\n");
    if (g_dlHandle != nullptr) {
        tlogw("tui daemon handle is opened");
        return true;
    }

#if defined(__LP64__)
    g_dlHandle = dlopen("/system/lib64/libcadaemon_tui.so", RTLD_LAZY);
#else
    g_dlHandle = dlopen("/system/lib/libcadaemon_tui.so", RTLD_LAZY);
#endif
    if (g_dlHandle == nullptr) {
        tlogi("tui daemon handle is null");
        return false;
    }

    g_tuiDaemonFunc = (bool(*)(int))dlsym(g_dlHandle, "TeeTuiDaemonWork");
    g_tuiIsFoldableFunc = (bool(*)())dlsym(g_dlHandle, "TeeTuiIsFoldable");
    if (g_tuiDaemonFunc == nullptr || g_tuiIsFoldableFunc == nullptr) {
        tloge("dlsym is null\n");
        (void)dlclose(g_dlHandle);
        g_dlHandle = nullptr;
        return false;
    }
    tlogi("tui daemon init success\n");
    return true;
}

static void TuiDaemonClean(void)
{
    tlogi("tui daemon clean\n");
    if (g_dlHandle == nullptr) {
        tlogw("tui daemon handle is not opened");
        return;
    }

    g_tuiDaemonFunc = nullptr;
    g_tuiIsFoldableFunc = nullptr;
    sleep(WAIT_BEFORE_DLCLOSE);
    (void)dlclose(g_dlHandle);
    g_dlHandle = nullptr;
}

void HandleEvent(const char *eventParam, int32_t paramLen)
{
    if (eventParam == nullptr || paramLen == 0) {
        return;
    }

    const char *str = eventParam;
    if (strncmp(str, "unused", sizeof("unused")) == 0) {
        tlogi("send false state to frame 1\n");
        if (g_tuiDaemonFunc != nullptr) {
            (void)g_tuiDaemonFunc(TUI_DAEMON_TUI_END);
            if (!g_tuiIsFoldableFunc()) {
                TuiDaemonClean();
            }
        }
    } else if (strncmp(str, "config", sizeof("config")) == 0) {
        tlogi("send true state to frame 1\n");
        if (TuiDaemonInit()) {
            (void)g_tuiDaemonFunc(TUI_DAEMON_TUI_START);
        }
    } else {
        tlogi("do not need send data\n");
    }

    return;
}

#define TUI_INIT_RETRY_TIMES 10
void TeeTuiThreadWork(void)
{
    tlogi("tee tui thread work\n");
    uint32_t count = 0;
    bool initFlag = false;
    while (count++ <= TUI_INIT_RETRY_TIMES) {
        if (TuiDaemonInit()) {
            initFlag = g_tuiDaemonFunc(TUI_DAEMON_TUI_INIT);
            TuiDaemonClean();
        }

        if (initFlag) {
            tlogi("tee tui daemon init success\n");
            break;
        }
        tlogi("tee tui daemon init retry %" PUBLIC "d \n", count);
        sleep(2); // 2 : sleep 2s
    }

    do {
        char eventParam[EVENT_PARAMS_LEN] = { 0 };
        int32_t paramLen = PARAMS_INPUT_LEN;
        int32_t ret = GetEvent(eventParam, &paramLen);
        if (ret == 0) {
            HandleEvent(eventParam, paramLen);
        } else {
            tloge("get event failed, something wrong\n");
            break;
        }
    } while (true);

    tlogi("tui thread loop stop\n");
    return;
}

#ifdef __cplusplus
}
#endif
