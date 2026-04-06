# Netch Go

[中文](README.md) | English

## Statement

This project is modified from [netchx/netch](https://github.com/netchx/netch).  
In this version, the frontend and backend are rewritten with Go + Wails, and the C++ Redirector core is also partially refactored.

## Positioning Difference vs Original Netch

This project is no longer a general "multi-mode, multi-protocol" proxy toolbox.  
It is focused on being a process-level force-proxy tool.

Main differences and advantages:

- TUN mode is removed.
- Multiple proxy types are removed; only SOCKS (SOCKS5) is kept.
- The workflow is centered on "Rule Set + Process Redirector".
- DNS redirect behavior is fixed and improved.
- DNS Client ETW domain monitoring is added to solve visibility issues when DNS is queried via `svchost.exe`.

## Requirements

- Windows
- Run as Administrator (`wails dev` or packaged `.exe`)
- Runtime artifacts must exist:
  - `runtime/bin/Redirector.bin`
  - `runtime/bin/nfapi.dll`
  - `runtime/bin/nfdriver.sys`

## Usage

### 1) Configure Server and Rule Set first

A Rule Set has three rule groups:

- Include rules: processes to be redirected (regex).
- Exclude rules: bypass when matched (regex, higher priority than include).
- Domain rules: DNS Client domain filtering rules (supports `*` wildcard).

Domain rule examples:

- `.example.com` (same as `*.example.com`)
- `*.example.net`
- `api.example.org`
- `*example.io`

### 2) Process Redirector options

`Intercept TCP / Intercept UDP / Intercept DNS` are the main traffic controls for matched processes:

- `Intercept TCP`: redirect outbound TCP from matched processes.
- `Intercept UDP`: redirect outbound UDP from matched processes.
- `Intercept DNS`: redirect DNS queries from matched processes.

Important DNS-related options:

- `Handle DNS Client`
  - Enabled: in addition to matched processes, DNS queries from Windows DNS Client (`svchost.exe`) are also handled.
  - Disabled: only DNS from matched processes is handled.
  - Why this matters: many unrelated applications also query DNS through `svchost.exe`, which can introduce unrelated DNS traffic.

- `DNS Client: Domain Rules Only`
  - Only meaningful when `Handle DNS Client` is enabled.
  - When enabled, only `svchost.exe` DNS queries matching domain rules are handled; non-matching ones are passed through.
  - This does not change DNS handling for directly matched target processes.
  - To see which domains matched processes are querying, use `DNS Client Monitor (ETW)`.

- `DNS Through Proxy`
  - DNS forwarding uses the SOCKS path.
  - SOCKS server must support SOCKS5 UDP Associate, otherwise UDP Associate errors will appear.

- `Remote DNS`
  - Example: `1.1.1.1:53`
  - If target DNS is private/internal, disabling `DNS Through Proxy` is usually recommended.

Other options (`Loopback`, `Intranet`, `Child process by parent`, `ICMP`) can be enabled as needed.

## What DNS Client Monitor (ETW) solves

### Problem

Many apps do not send DNS queries directly.  
They delegate DNS queries to Windows DNS Client (`svchost.exe`), so you may see connections but cannot easily see real queried domains.

### What it does

`DNS Client Monitor (ETW)` reads `Microsoft-Windows-DNS-Client/Operational` events in real time, extracting:

- `QueryName`
- `ClientPID`

Then it filters by current Rule Set process matching and only shows related domains in the "Real-time Domains" panel.

### Startup checks

- Check whether DNS Client ETW channel is enabled.
- Check whether force-proxy service is currently running (must be stopped first).
- Run `ipconfig /flushdns` to reduce cache interference.
- Start real-time capture and display domains related to matched rules/processes.

### How to enable/disable Windows DNS Client ETW channel

Run in an Administrator terminal:

Enable:

```powershell
wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true
```

Disable:

```powershell
wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:false
```

Check current status:

```powershell
wevtutil gl Microsoft-Windows-DNS-Client/Operational
```

`enabled: true` means ETW channel is enabled.  
After that, turn on `DNS Client Monitor (ETW)` in the app UI.

## Development and Build (Quick)

Build native core and copy runtime artifacts:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build-native.ps1 -Configuration Release
```

Local development:

```powershell
wails dev
```

Package release build:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\package-release.ps1 -Configuration Release -SkipNativeBuild
```
