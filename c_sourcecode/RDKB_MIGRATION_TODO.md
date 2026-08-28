# RDKB (Broadband/Extender) C Migration TODO

Reference scripts: `uploadDumpsRDKB.sh` (main flow), `uploadDumpsToS3.sh` (S3 upload logic)  
Reference RDKC C migration: `src/upload/upload.c` RDKC block, `src/archive/archive.c` RDKC block  
Common APIs available: `commonutilities` → `common_device_api.h`, `system_utils.h`, `rdk_fwdl_utils.h`, `uploadutils/mtls_upload.h`

---

## Status: Already Done / Not Required

| # | Script item | C status | Note |
|---|---|---|---|
| – | `CORE_PATH="/minidumps"` broadband; `MINIDUMPS_PATH="/minidumps"` broadband/extender | ✅ Done | `config_manager.c` lines 236, 262 |
| – | `if [ ! -e $CORE_PATH/*.dmp ]; then exit 0; fi` broadband/extender | ✅ Done | `has_required_dumps()` in `prerequisites.c` checks `.dmp` per device type |
| – | `touch /tmp/crash_reboot` in `finalize()` | ✅ Done | `main.c` cleanup block |
| – | `TLS="--tlsv1.2"` for broadband | ✅ Done | TLS 1.2 is the compiled-in default |
| – | `CURL_LOG_OPTION` empty for broadband | ✅ Not required | No equivalent needed in C upload path |
| – | Network check / `network_commn_status` broadband/extender | ✅ Not required | User confirmed: no network prereq check needed |
| – | Network availability skip on upload path | ✅ Not required | Skipped by design |
| – | `GetModelNum` for broadband | ✅ Works | `GetModelNum()` in `common_device_api.c` reads `MODEL_NUM=` from `/etc/device.properties` — same source as `$MODEL_NUM` env var in script. Already called in `platform.c`. |

---

## Sorted TODO Table

### TRIVIAL — constants / comments only, zero risk

| ID | Status | File | What | Notes |
|---|---|---|---|---|
| T1 | ✅ Completed | `config_manager.c` | `/opt/coredump.properties` reference comment | Added inline in broadband config block. |
| T2 | ✅ Completed | `upload.c` | Portal URL, `request_type=18`, `encryptionEnable` via syscfg | `RDKB_PORTAL_DEFAULT_URL`, `request_type=18`; syscfg via `v_secure_popen`; extender shares branch. |

---

### EASY — known pattern, no new dependencies

| ID | Status | File | What | Notes |
|---|---|---|---|---|
| E1 | ✅ Completed | `archive.c` | Broadband/extender minidump tar branch | `BROADBAND\|\|EXTENDER` block: `dumpName + /version.txt + core_log_file`. |
| E2 | ✅ Completed | `archive.c` | Broadband/extender success log | Already covered by shared `device_type_to_str()` log path. |
| E3 | ✅ Completed | `upload.c` | Extender partner ID from account JSON | Reads `/opt/persistent/account` via `strstr("partnerId")`. Broadband uses `GetPartnerId()`. |
| E4 | ✅ Completed | `platform.c/h` | `get_core_type()` + `get_interface_value()` | `get_core_type()`: cached `/tmp/cpu_info` → `/proc/cpuinfo`. `get_interface_value()`: polls `sysevent get current_wan_ifname` up to 900s; fallback ATOM/ARM→device.properties interface key. |

---

### MEDIUM — needs a known API call we can make

| ID | Status | File | What | Notes |
|---|---|---|---|---|
| M1 | ✅ Completed | `upload.c` | `encryptionEnable` — syscfg primary, rbus fallback | `v_secure_popen(syscfg)` first; `rbus_get_string_param(RFC_DMP_ENCRYPT_UPLOAD)` if empty. |
| M2 | ✅ Completed | `config_manager.c` | `COMM_INTERFACE` no-multi-core path | `getDevicePropertyData("INTERFACE", config->comm_interface, ...)`. |
| M3 | ✅ Completed | `upload.c` | S3 signing URL for broadband via rbus | `rbus_get_string_param(RDKB_SYNDICATION_CRASH_PORTAL)` first; fallback to `get_crashupload_s3signed_url()`. |
| M4 | 🚫 Ignored | `upload.c` | IF_OPTION for extender — WAN interface binding | `ARM_INTERFACE` from device.properties now handled via D1/get_core_type path. Extender uses same code path. |

---

### DIFFICULT — external/RDKB-specific library or unknown source

| ID | Status | File | What | Blocker |
|---|---|---|---|---|
| D1 | ✅ Completed | `config_manager.c` | `COMM_INTERFACE` broadband `MULTI_CORE=yes` | `get_core_type()` detects ARM; uses `ARM_INTERFACE` from device.properties; falls back to `INTERFACE`. |
| D2 | 🚫 Ignored | `upload.c` | `encryptionEnable` XB3/rpcclient fallback chain | User confirmed: XB3 path not needed. `v_secure_popen(syscfg)` + rbus fallback (M1) is sufficient. |
| D3 | ✅ Completed | `upload.c` | sky-uk EU S3 URL fallback | `S3_AMAZON_SIGNING_URL_EU` confirmed in `/etc/device.properties`. `getDevicePropertyData("S3_AMAZON_SIGNING_URL_EU")` when partnerID=sky-uk and rbus URL is empty. |

---

### NEEDS ANALYSIS / LIBRARY INTEGRATION

| ID | Status | File | What | What we know / don't know |
|---|---|---|---|---|
| N1 | ✅ Completed | `platform.c` | `GetModelNum` for extender via `mfr_util` | `GetModelNum()` reads `MODEL_NUM=` from `/etc/device.properties` — equivalent to script fallback `$MODEL_NUM`. Sufficient without mfrapi. |
| N2 | ✅ Completed | `config_manager.c` + `platform.c` | IF_OPTION broadband MULTI_CORE=yes + `get_core_type` | `get_core_type()` (E4) + `ARM_INTERFACE`/`INTERFACE` from device.properties now wired in D1. |

---

## Dependency Map

```
T2 (portal URL) → required before upload.c broadband block is useful
E1 (archive tar) → required for any upload to happen on broadband/extender
M1 (encryptionEnable via rbus) → required for S3 MD5 decision
M3 (S3 URL via rbus) → required for broadband S3 upload
E4 (get_core_value) → feeds into N2 (IF_OPTION multi-core)
rbus_interface.c stub → must be implemented before M1, M3, D1
```

## Recommended Implementation Order

1. **T2, E1, E2** — unblocks basic end-to-end broadband/extender archive+upload with hardcoded portal; no new deps
2. **E3** — extender partner ID; pure C file parsing
3. **M2** — COMM_INTERFACE no-multi-core from device.properties; one `getDevicePropertyData` call
4. **E4** — get_core_value; pure C /proc parsing
5. **M1 + M3** — implement `rbus_interface.c` (`rbus_init` + `rbus_get_string_param`), then use for encryption flag and S3 URL
6. **N1** — extender model number; confirm whether device.properties fallback in `GetModelNum` is sufficient before pulling in mfrapi
7. **D1, D2, N2, D3** — defer until rbus is confirmed working and device-level data is available
