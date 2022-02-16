# TeeClient组件<a name="ZH-CN_TOPIC_0000001148528849"></a>

-   [简介](#section11660541593)
-   [目录](#section161941989596)
-   [相关仓](#section1371113476307)

## 简介<a name="section11660541593"></a>

TeeClient 向应用提供访问安全OS（TEEOS）能力，让非安全侧应用可以访问安全OS内运行的安全应用。

TeeClient模块可以分为如下三大部分：

-   TeeClient SDK层：提供TeeClient API供应用调用，标准系统提供libteec.z.so库，小型化系统提供libteec_vendor.so。
-   TeeClient 基础服务层：包括teecd、tlogcat服务，标准系统及小型化系统均提供。teecd为TEEOS实现安全存储、时间同步等基础功能，tlogcat为TEEOS日志输出及落盘服务。
-   TeeClient 服务层：为应用访问TEEOS提供能力的服务，在标准系统提供；小型化系统不需要，应用可直接访问TEEOS能力。

## 目录<a name="section161941989596"></a>

```
base/tee/tee_client
├── libteec
│   ├── frameworks
│   │   ├── build                          # sdk库编译配置文件，在标准及小型化系统使能
│   │   │   ├── lite                       # 标准系统sdk库编译配置文件
│   │   │   └── standard                   # 小型化系统sdk库编译配置文件
│   │   ├── libteec_client                 # 标准系统sdk库实现代码
│   │   └── libteec_vendor                 # 小型化系统sdk库实现代码
│   ├── interfaces                         # teeClient对外头文件
│   │   └── libteec
│   └── services                           # 标准系统给上层应用提供访问TEEOS的服务
│       ├── build
│       │   └── standard
│       └── src
├── teecd                                  # 为TEEOS实现安全存储、时间同步等基础功能，在标准及小型化系统使能
│   ├── build
│   │   ├── lite
│   │   └── standard
│   └── src
└── tlogcat                                # TEEOS日志输出及落盘服务，在标准及小型化系统使能
    ├── build
    │   ├── lite
    │   └── standard
    └── src
```

## 相关仓<a name="section1371113476307"></a>

**tee子系统**

**tee_client**


