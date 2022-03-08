# TeeClient<a name="EN-US_TOPIC_0000001148528849"></a>

-   [Introduction](#section11660541593)
-   [Directory Structure](#section161941989596)
-   [Repositories Involved](#section1371113476307)

## Introduction<a name="section11660541593"></a>

TeeClient provides applications with access to secure OS (TEEOS) capabilities, allowing applications to access security applications running inside the secure OS.

TeeClient consists of the following modules:

- TeeClient SDK layer：Provide TeeClient API for application calls,  provides libteec.z.so library for standard, provides libteec_vendor.so for lite.
- TeeClient base service layer：Including teecd and tlogcat services, provides for both standard and lite. teecd assists TEEOS to achieve basic functions such as secure storage and time synchronization, and tlogcat provides TEEOS log output services.
- TeeClient service layer：The service provides the ability for applications to access TEEOS, only used in standard system. In lite system, the application will directly accesses the TEEOS capability.

## Directory Structure<a name="section161941989596"></a>

```
base/tee/tee_client
├── frameworks
│   ├── build                          # sdk library compilation configuration file, enabled in standard and lite systems
│   │   ├── lite                       # Standard system sdk library compilation configuration file
│   │   └── standard                   # Lite system sdk library compilation configuration file
│   ├── libteec_client                 # Standard system sdk library implementation code
│   └── libteec_vendor                 # Lite system sdk library implementation code
├── interfaces                         # TeeClient sdk header files for applications
│   └── libteec
└── services
    ├── cadaemon                       # In standard system, provides applications with access to TEEOS services
    |   ├── build
    |   │   └── standard
    |   └── src
    ├── teecd                          # Implement basic functions such as secure storage and time synchronization for TEEOS,
                                       # enabling it in standard and lite systems
    │   ├── build
    │   │   ├── lite
    │   │   └── standard
    │   └── src
    └── tlogcat                        # TEEOS log output service, enabled in standard and lite systems
        ├── build
        │   ├── lite
        │   └── standard
        └── src
```

## Repositories Involved<a name="section1371113476307"></a>

**tee subsystem**

tee_client
