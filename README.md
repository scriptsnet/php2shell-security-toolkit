# PHP2Shell Security Toolkit

用于检查、取证与安全修复 **CVE-2026-109618 / CVE-2026-109619**（PHP2Shell）的多服务器工具包。

[中文](#中文) · [English](#english) · [事件报告](docs/incident-report.zh-CN.md) · [Incident report](docs/incident-report.en.md)

当前发布：**1.0.2**（2026-10-22）

已构建下载：

- [GitHub Release v1.0.2](https://github.com/scriptsnet/php2shell-security-toolkit/releases/tag/v1.0.2)
- [Windows PC 扫描器](https://github.com/scriptsnet/php2shell-security-toolkit/releases/download/v1.0.2/PHP2ShellScanner-PC.exe)
- [Windows Web 扫描器](https://github.com/scriptsnet/php2shell-security-toolkit/releases/download/v1.0.2/PHP2ShellScanner-Web.exe)
- [完整源码/文档包](https://github.com/scriptsnet/php2shell-security-toolkit/releases/download/v1.0.2/php2shell-scanner-1.0.2.zip)
- [Linux + Windows Server 修复脚本](https://github.com/scriptsnet/php2shell-security-toolkit/releases/download/v1.0.2/php2shell-server-scripts-1.0.2.zip)
- [SHA256 校验值](https://github.com/scriptsnet/php2shell-security-toolkit/releases/download/v1.0.2/SHA256SUMS.txt)

## 中文

PHP 于 2026-10-21 14:00 UTC（北京时间 22:00）发布紧急安全版本。两个漏洞都位于 PHP 运行时，可导致未认证远程代码执行；应用、插件或 CMS 自身升级不能替代 PHP 升级。

| PHP 分支 | 受影响版本 | 官方修复版本 |
| --- | --- | --- |
| 8.5 | `< 8.5.12` | `8.5.12` |
| 8.4 | `< 8.4.27` | `8.4.27` |
| 8.3 | `< 8.3.36` | `8.3.36` |
| 8.2 | `< 8.2.35` | `8.2.35` |
| 8.1 及更早 | 上游 EOL | 无新的官方发行版；升级或使用发行版/LTS 厂商回溯补丁 |

> **修复完成的条件是：补丁已安装，并且所有旧 PHP 进程都已完整重启。** 仅执行 `docker restart` 不会把旧容器带到新镜像；只执行软件包升级也不会替换正在运行的旧 PHP-FPM/Apache worker。

服务器端还提供可直接上传运行的全流程检查/修复脚本：

- [Linux 全流程脚本](server/php2shell-fullfix-linux.sh)
- [Windows Server/NT 本机全流程脚本](server/php2shell-fullfix-windows.ps1)
- [服务器脚本说明](server/README.md)

全流程脚本默认只检查；修复模式会在任何变更前备份 PHP，并要求三次风险/快照/回滚确认。Windows 脚本应放到实际运行 PHP 的 Windows Server/NT 服务器本机执行，不是拿个人 PC 充当服务器。

完整背景、时间线、来源、攻击条件与生产处置顺序见：

- [中文事件报告与修复指南](docs/incident-report.zh-CN.md)
- [English incident report and remediation guide](docs/incident-report.en.md)
- [安全模型与边界](SECURITY.md)

## 安全边界

- 不发送漏洞利用载荷。
- 不自动升级、不自动改配置、不删除远程文件。
- SSH 端只运行固定的只读盘点脚本。
- 不接收或保存服务器密码；使用 OpenSSH 私钥或 `ssh-agent`。
- 首次连接采用 `StrictHostKeyChecking=accept-new`；主机指纹变化后会拒绝连接。
- Web 版默认只监听 `127.0.0.1`。绑定非本机地址时必须设置访问 token。

## 能检查什么

- Linux 主机上 PATH、`/www/server/php`、`/usr/local`、`/opt` 下的 PHP / FPM / CGI。
- Docker 容器内的 PHP。
- CLI、FPM、CGI、Apache mod_php 等 SAPI。
- `memory_limit`、`post_max_size`、`session.upload_progress.enabled` 等配置。
- 系统包、PHP-FPM 服务、运行进程和 pool 级覆盖配置。
- HTTP 目标暴露的 `X-Powered-By`、`Server`、`PHP/8.x.x` 和 `PHPSESSID` 指纹。

HTTP 指纹不是权威资产盘点。如果目标隐藏 PHP 版本，必须用 SSH 模式或主机 Agent 扫描。

## 当前边界

- 远程批量盘点面向 Linux + OpenSSH；Windows Server/NT 请把 `server/php2shell-fullfix-windows.ps1` 放到对应服务器本机执行。PC/Web 扫描端对 Windows 目标仍主要依赖 HTTP 指纹。
- 扫描器没有自动修复功能，修复步骤是为了审计和执行而生成。
- HTTP 模式无法证明 PHP 不存在；响应头隐藏时会明确标为“无法确认”。
- 单次 Web 任务最多 1000 个目标，最多同时运行 3 个任务。

## 判定规则

| PHP 分支 | 受影响 | 修复版本 |
| --- | --- | --- |
| 8.5 | `< 8.5.12` | `8.5.12` |
| 8.4 | `< 8.4.27` | `8.4.27` |
| 8.3 | `< 8.3.36` | `8.3.36` |
| 8.2 | `< 8.2.35` | `8.2.35` |

PHP 8.1 及以下会标记为高风险/EOL。PHP 8.6 RC 或未知分支会要求人工复核。

## 服务器清单

CSV：

```csv
name,host,port,user,key_path
web-prod,192.0.2.10,2222,deploy,C:\Users\demo\.ssh\id_ed25519
web-backup,198.51.100.20,2222,ops,
```

也支持每行简写：

```text
deploy@192.0.2.60:2222
198.51.100.61
```

私钥留空时使用 `ssh-agent` 或 OpenSSH 默认密钥。带口令的密钥建议先加入 `ssh-agent`。

## PC 版

开发运行：

```powershell
cd D:\testme\php2shell-scanner
python pc_app.py
```

打包：

```powershell
.\build.ps1
```

输出：

```text
dist\PHP2ShellScanner-PC.exe
```

当前可执行文件未做商业代码签名，Windows SmartScreen 可能提示“未知发布者”。

PC 版支持导入 CSV、批量并发扫描、查看证据，并导出 HTML / CSV / JSON。

## Web 版

开发运行：

```powershell
cd D:\testme\php2shell-scanner
python web_app.py
```

默认打开 `http://127.0.0.1:8765/`。打包后运行：

```powershell
dist\PHP2ShellScanner-Web.exe
```

当前可执行文件未做商业代码签名，Windows SmartScreen 可能提示“未知发布者”。

如果必须从其他电脑访问 Web 版：

```powershell
python web_app.py --host 0.0.0.0 --port 8765 --token "换成长随机字符串"
```

Web 版中的 SSH 私钥路径是“运行扫描后端那台机器”的本地路径，不是浏览器电脑的路径。生产使用不要上传私钥到共享 Web 服务。

## CLI

```powershell
python cli_app.py --servers-file samples\servers.csv --targets-file samples\targets.txt --format html --output reports\scan.html
```

## 修复建议如何生成

扫描器会区分：

- 源码安装路径：给出官方源码版本、备份、编译、FPM 配置测试和完整重启步骤。
- 发行版包：要求以 CVE 跟踪页或 USN/DSA/RHSA 的 `Fixed` 状态为准。
- Docker：要求更新镜像并重建容器，明确禁止只执行 `docker restart`。
- EOL 分支：要求升级到受支持稳定分支或取得厂商回溯补丁。

扫描器只给路径，不自动执行修复。

## 自检

```powershell
python -m unittest discover -s tests -v
python pc_app.py --self-test
python web_app.py --self-test
```

发布前验证：

```powershell
python -m unittest discover -s tests -v
python pc_app.py --self-test
python web_app.py --self-test
```

## English

This repository contains a read-only inventory scanner plus guarded Linux and Windows Server remediation scripts for **CVE-2026-109618** and **CVE-2026-109619**, collectively named PHP2Shell.

PHP released the following fixed versions on October 21, 2026 at 14:00 UTC: **8.2.35, 8.3.36, 8.4.27, and 8.5.12**. Every earlier release in those branches is affected. PHP 8.1 and older are end-of-life upstream; use a vendor/LTS backport or upgrade to a supported branch.

The scanner deliberately does not send exploit payloads. It inventories local PHP binaries, web SAPIs, Docker runtimes, package clues, security-relevant INI settings, and passive HTTP banner information. A hidden banner is reported as unknown, never as safe.

The full Linux and Windows Server scripts run in check-only mode by default. Apply mode requires a full-machine snapshot acknowledgement, backs up the managed PHP installation, and generates a component-specific rollback script before making changes.

Read the [English incident report](docs/incident-report.en.md) before using any remediation script in production.

Prebuilt Windows executables, source archives, server scripts, and checksums are hosted on the GitHub Release linked above.

## License

MIT. See [LICENSE](LICENSE).

---

## ☕ Support this project

如果这份事件报告、扫描器或修复脚本帮你节省了排查时间，欢迎点一个 ⭐，或扫码支持后续维护。

If this incident report, scanner, or remediation toolkit saved you time, a ⭐ is already a great support. You can also use the QR codes below to support ongoing maintenance.

<div align="center">

**感谢支持 / Thank you for your support ☕**

| 微信 / WeChat | 支付宝 / Alipay |
|:---:|:---:|
| <img src="docs/wechat-pay.png" width="220" alt="微信收款码 / WeChat payment QR"> | <img src="docs/alipay-pay.jpg" width="220" alt="支付宝收款码 / Alipay payment QR"> |

</div>
