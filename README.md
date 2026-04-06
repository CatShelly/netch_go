# Netch Go

## 声明

本项目基于项目 [netchx/netch](https://github.com/netchx/netch) 修改而来。  
当前版本的前后端已使用 Go + Wails 重写，C++ Redirector 内核也做了针对性改造。

## 这个版本和原项目的定位差异

这个项目不再追求“多模式、多协议”的通用代理工具定位，而是聚焦为一个更直接的进程强制代理工具。

主要差异与优势：

- 移除了 TUN 模式。
- 移除了多种代理方式，仅保留 SOCKS（SOCKS5）链路。
- 以“规则集 + 进程重定向”为核心，配置和行为更聚焦。
- 修复并强化了 DNS 重定向相关逻辑。
- 增加 DNS Client ETW 域名监听能力，用于解决 svchost 代查 DNS 时的可观测性问题。

## 运行要求

- Windows
- 管理员权限运行（`wails dev` 或打包后的 exe 都一样）
- 运行时组件齐全：
  - `runtime/bin/Redirector.bin`
  - `runtime/bin/nfapi.dll`
  - `runtime/bin/nfdriver.sys`

## 使用说明

### 1) 先配置服务器和规则集

规则集包含三类规则：

- 包含规则：哪些进程要被接管（正则）。
- 绕过规则：命中后不接管（正则，优先级高于包含规则）。
- 域名规则：用于 DNS Client 域名过滤（支持 `*` 通配符）。

域名规则示例：

- `.example.com`（等价于 `*.example.com`）
- `*.example.net`
- `api.example.org`
- `*example.io`

### 2) 进程重定向选项

`拦截 TCP / 拦截 UDP / 拦截 DNS` 这三个开关都属于“命中规则进程”的接管范围，建议放在一起理解：

- `拦截 TCP`：接管命中进程的 TCP 出站连接。
- `拦截 UDP`：接管命中进程的 UDP 出站流量。
- `拦截 DNS`：接管命中进程的 DNS 查询流量。

DNS 相关重点开关：

- `对DNS Client进行DNS处理`
  - 勾选：除了命中规则进程外，还会处理 DNS Client（`svchost.exe`）发起的 DNS 请求。
  - 不勾选：只处理命中规则进程本身发出的 DNS。
  - 但是除了命中规则进程外，还有很多其他进程也同样通过svchost.exe进行DNS请求，这会导致很多不相关进程的DNS请求也被代理了，这时就需要`DNS Client仅对命中域名规则进行DNS处理`。

- `DNS Client仅对命中域名规则进行DNS处理`
  - 只有在勾选 `对DNS Client进行DNS处理` 时才有意义。
  - 开启后，仅 `svchost.exe` 路径会按“域名规则”过滤；未命中域名规则的 DNS 会直接放行。
  - 不影响“命中规则进程本身”的 DNS 处理逻辑。
  - 如何知道命中规则进程查询了哪些域名呢？请看`DNS Client 监听（ETW）`。

- `DNS 请求走代理`
  - DNS 转发到远端 DNS 时，走 SOCKS 链路。
  - 代理端需要支持 SOCKS5 UDP Associate；不支持时会出现 UDP Associate 失败日志。

- `重定向 DNS 目标`
  - 例如 `1.1.1.1:53`。
  - 若目标是内网 DNS，通常建议关闭“DNS 请求走代理”。

其他选项（如回环/内网/子进程/ICMP）按需启用即可。

## DNS Client 监听（ETW）有什么用

### 要解决的问题

很多程序的 DNS 查询并不是由目标进程自己直接发出，而是委托给 Windows DNS Client（`svchost.exe`）。  
这会导致“看见了连接，但看不见真实查了哪些域名”，调试规则和 DNS 行为非常困难。

### 这个功能做了什么

`DNS Client 监听（ETW）` 会实时读取 `Microsoft-Windows-DNS-Client/Operational` 事件，提取：

- 查询域名（`QueryName`）
- 客户端 PID（`ClientPID`）

然后按当前规则集做进程匹配过滤，只显示与命中规则进程相关的域名到“实时域名”面板。

### 开启时的检查流程

- 检查 DNS Client ETW 通道是否已启用。
- 检查强制代理是否正在运行（运行中会提示先停服务）。
- 先执行 `ipconfig /flushdns`，减少旧缓存干扰。
- 通过后开始实时抓取并显示域名，只会显示和命中规则有关的进程进行的dns请求域名。

### 如何开启与关闭 Windows DNS Client ETW 通道

请在管理员终端执行：

开启：

```powershell
wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true
```

关闭：

```powershell
wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:false
```

查看当前是否已开启：

```powershell
wevtutil gl Microsoft-Windows-DNS-Client/Operational
```

输出里 `enabled: true` 表示已开启。通道开启后，再回到程序里打开 `DNS Client 监听（ETW）` 开关即可开始抓取。

## 开发与构建（简版）

构建 C++ 内核并复制到运行时目录：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build-native.ps1 -Configuration Release
```

本地调试：

```powershell
wails dev
```

打包可执行（项目内脚本）：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\package-release.ps1 -Configuration Release -SkipNativeBuild
```
