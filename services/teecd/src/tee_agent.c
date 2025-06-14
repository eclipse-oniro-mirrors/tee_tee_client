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

#include "tee_agent.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "tee_ca_daemon.h"
#include "fs_work_agent.h"
#include "late_init_agent.h"
#include "misc_work_agent.h"
#include "secfile_load_agent.h"
#include "tc_ns_client.h"
#include "tee_load_dynamic.h"
#include "tee_log.h"
#include "tcu_authentication.h"
#include "tee_file.h"
#ifdef LOG_TAG
#undef LOG_TAG
#endif
#define LOG_TAG "teecd"

/* smc dev */
static int g_fsFd   = -1;
static int g_miscFd = -1;

int GetMiscFd(void)
{
    return g_miscFd;
}

int GetFsFd(void)
{
    return g_fsFd;
}

static int AgentInit(unsigned int id, void **control)
{
    int ret;
    struct AgentIoctlArgs args = { 0 };

    if (control == NULL) {
        return -1;
    }
    int fd = tee_open(TC_PRIVATE_DEV_NAME, O_RDWR, 0);
    if (fd < 0) {
        tloge("open tee client dev failed, fd is %" PUBLIC "d\n", fd);
        return -1;
    }

    /* register agent */
    args.id         = id;
    args.bufferSize = TRANS_BUFF_SIZE;
    ret             = ioctl(fd, (int)TC_NS_CLIENT_IOCTL_REGISTER_AGENT, &args);
    if (ret) {
        (void)tee_close(&fd);
        tloge("ioctl failed\n");
        return -1;
    }

    *control = args.buffer;
    return fd;
}

static void AgentExit(unsigned int id, int fd)
{
    int ret;

    if (fd == -1) {
        return;
    }

    ret = ioctl(fd, (int)TC_NS_CLIENT_IOCTL_UNREGISTER_AGENT, id);
    if (ret) {
        tloge("ioctl failed\n");
    }

    tee_close(&fd);
}

static struct SecStorageType *g_fsControl                = NULL;
static struct MiscControlType *g_miscControl             = NULL;
static struct SecAgentControlType *g_secLoadAgentControl = NULL;

static int g_fsThreadFlag = 0;

static int ProcessAgentInit(void)
{
    int ret;
    g_fsFd = AgentInit(AGENT_FS_ID, (void **)(&g_fsControl));
    if (g_fsFd < 0) {
        tloge("fs agent init failed\n");
        g_fsThreadFlag = 0;
    } else {
        g_fsThreadFlag = 1;
    }

    g_miscFd = AgentInit(AGENT_MISC_ID, (void **)(&g_miscControl));
    if (g_miscFd < 0) {
        tloge("misc agent init failed\n");
        goto ERROR1;
    }

    ret = AgentInit(SECFILE_LOAD_AGENT_ID, (void **)(&g_secLoadAgentControl));
    if (ret < 0) {
        tloge("secfile load agent init failed\n");
        goto ERROR2;
    }

    SetSecLoadAgentFd(ret);

    return 0;
ERROR2:
    AgentExit(AGENT_MISC_ID, g_miscFd);
    g_miscFd      = -1;
    g_miscControl = NULL;

ERROR1:
    if (g_fsThreadFlag == 1) {
        AgentExit(AGENT_FS_ID, g_fsFd);
        g_fsFd         = -1;
        g_fsControl    = NULL;
        g_fsThreadFlag = 0;
    }
    return -1;
}

static void ProcessAgentExit(void)
{
    if (g_fsThreadFlag == 1) {
        AgentExit(AGENT_FS_ID, g_fsFd);
        g_fsFd      = -1;
        g_fsControl = NULL;
    }

    AgentExit(AGENT_MISC_ID, g_miscFd);
    g_miscFd      = -1;
    g_miscControl = NULL;

    AgentExit(SECFILE_LOAD_AGENT_ID, GetSecLoadAgentFd());
    SetSecLoadAgentFd(-1);
    g_secLoadAgentControl = NULL;
}

static int SyncSysTimeToSecure(void)
{
    TC_NS_Time tcNsTime;
    struct timeval timeVal;

    int ret = gettimeofday(&timeVal, NULL);
    if (ret != 0) {
        tloge("get system time failed ret=0x%" PUBLIC "x\n", ret);
        return ret;
    }
    if (timeVal.tv_sec < 0xFFFFF) {
        return -1;
    }
    tcNsTime.seconds = (uint32_t)timeVal.tv_sec;
    tcNsTime.millis  = (uint32_t)timeVal.tv_usec / 1000;

    int fd = tee_open(TC_PRIVATE_DEV_NAME, O_RDWR, 0);
    if (fd < 0) {
        tloge("Failed to open %" PUBLIC "s: %" PUBLIC "d\n", TC_PRIVATE_DEV_NAME, errno);
        return fd;
    }
    ret = ioctl(fd, (int)TC_NS_CLIENT_IOCTL_SYC_SYS_TIME, &tcNsTime);
    if (ret != 0) {
        tloge("failed to send sys time to teeos\n");
    }

    tee_close(&fd);
    return ret;
}

void TrySyncSysTimeToSecure(void)
{
    static int syncSysTimed = 0;

    if (syncSysTimed == 0) {
        int ret = SyncSysTimeToSecure();
        if (ret != 0) {
            tloge("failed to sync sys time to secure\n");
        } else {
            syncSysTimed = 1;
        }
    }
}

int main(void)
{
    pthread_t fsThread               = (pthread_t)-1;
    pthread_t miscThread             = (pthread_t)-1;
    pthread_t caDaemonThread         = (pthread_t)-1;
#ifdef CONFIG_LATE_INIT
    pthread_t lateInitThread         = (pthread_t)-1;
#endif
    pthread_t secfileLoadAgentThread = (pthread_t)-1;

    /* Trans the xml file to tzdriver: */
    (void)TcuAuthentication(HASH_TYPE_WHOLE);

    int ret = ProcessAgentInit();
    if (ret) {
        return ret;
    }

    TrySyncSysTimeToSecure();

    SetFileNumLimit();

    /* Since sfs is accessed during the first sec file load,
       the fs agent thread needs to be initialized before the first sec file is loaded */
    if (g_fsThreadFlag == 1) {
        (void)pthread_create(&fsThread, NULL, FsWorkThread, g_fsControl);
    }

#ifdef DYNAMIC_CRYPTO_DRV_DIR
    LoadDynamicCryptoDir();
#endif

#ifdef DYNAMIC_DRV_DIR
    LoadDynamicDrvDir(NULL, 0);
#endif

#ifdef DYNAMIC_SRV_DIR
#ifndef DYNAMIC_SRV_DIR_LOAD_LATE
    LoadDynamicSrvDir();
#endif
#endif

    (void)pthread_create(&caDaemonThread, NULL, CaServerWorkThread, NULL);

#ifdef DYNAMIC_SRV_DIR
#ifdef DYNAMIC_SRV_DIR_LOAD_LATE
    LoadDynamicSrvDir();
#endif
#endif

    (void)pthread_create(&miscThread, NULL, MiscWorkThread, g_miscControl);
#ifdef CONFIG_LATE_INIT
    (void)pthread_create(&lateInitThread, NULL, InitLateWorkThread, NULL);
#endif
    (void)pthread_create(&secfileLoadAgentThread, NULL, SecfileLoadAgentThread, g_secLoadAgentControl);

    if (g_fsThreadFlag == 1) {
        (void)pthread_join(fsThread, NULL);
    }
    (void)pthread_join(miscThread, NULL);
    (void)pthread_join(caDaemonThread, NULL);
#ifdef CONFIG_LATE_INIT
    (void)pthread_join(lateInitThread, NULL);
#endif
    (void)pthread_join(secfileLoadAgentThread, NULL);

    ProcessAgentExit();
    return 0;
}
