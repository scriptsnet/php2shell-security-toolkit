# PHP2Shell 事件报告与服务器修复指南

更新：2026-10-22（Asia/Shanghai）

## 结论

2026-10-21 14:00 UTC（北京时间 22:00），PHP 发布紧急安全版本，修复两个可导致未认证远程代码执行的运行时漏洞：

| CVE | 问题类型 | 官方 CVSS v4.0 | 修复提交/公告 |
| --- | --- | --- | --- |
| CVE-2026-109618 | 内存耗尽（OOM）时请求状态损坏，清理阶段可能把无效状态当成有效数据 | 9.2 | GHSA-w8hw-w9fx-j79w |
| CVE-2026-109619 | 跨请求保留的陈旧全局状态指向已释放内存，后续请求可触发 use-after-free | 9.2 | GHSA-6wmf-4rv5-p3rp |

漏洞位于 PHP 核心，不在 WordPress、Laravel、Drupal 或单一插件中。所有处理 Web 请求的 PHP SAPI 都应纳入排查，包括 PHP-FPM、Apache `mod_php`、`php-cgi`、FrankenPHP 和 LiteSpeed。PHP 认为 `mod_php` 风险最高，因为已演示可在应用代码执行前通过未认证请求触发。

## 受影响与修复版本

| PHP 分支 | 受影响范围 | 官方修复版 |
| --- | --- | --- |
| 8.5 | 低于 8.5.12 | 8.5.12 |
| 8.4 | 低于 8.4.27 | 8.4.27 |
| 8.3 | 低于 8.3.36 | 8.3.36 |
| 8.2 | 低于 8.2.35 | 8.2.35 |
| 8.1 及更早 | 上游 EOL | PHP 提供 7.4/8.0/8.1 最小源码回溯补丁，但没有新的官方二进制发行版 |

发行版可能用原始版本号携带回溯修复。例如系统显示 8.2.x 低于 8.2.35 时，不能只凭版本号断定未修复；必须检查 Ubuntu、Debian、Red Hat、AlmaLinux、Rocky Linux 或 LTS 厂商公告和软件包变更记录。

## 漏洞条件与影响

### CVE-2026-109618

PHP 通过 `longjmp()` 处理部分 OOM 情况。请求内存尚未完整初始化时若发生分配失败，退出路径可能没有正确收尾，请求 shutdown 阶段会处理无效状态。多段 multipart 请求可放大攻击面，包括无可用 `Content-Length`、单个 part 包含大量 header、空文件控件以及深层嵌套字段名。

已确认攻击可在 Apache `mod_php` 上于应用代码运行之前发生。FPM 源码分析支持其同样 susceptible，但公开公告未声称完成了完整的 FPM 利用链；FrankenPHP 被判断为很可能受影响，LSAPI 与应用行为有关。安全处置不能因“用的是 FPM”而降低优先级。

### CVE-2026-109619

某个请求在致命错误、超时或 OOM 等异常路径中退出后，PHP worker 的全局字段仍可能引用该请求拥有的内存。请求堆被释放后，同一 worker 处理下一个请求时，某些在正常初始化前运行的操作可能读取、释放或分支于陈旧状态。

已确认的 consumer 包括 session upload progress，以及在 PHP 8.5 上启用 `fatal_error_backtraces` 时的致命错误回溯路径。Apache `.htaccess`/目录级 PHP 配置，以及 FPM 前端传递的 `PHP_VALUE`/`PHP_ADMIN_VALUE`，还可能形成配置诊断类早期 consumer。

成功利用可能以 Web worker 权限执行代码、读取进程可见数据或造成拒绝服务。版本修复后仍应检查修复前的可疑行为，因为 web shell、计划任务、异常进程与凭据泄露不会因升级 PHP 自动消失。

## 官方临时缓解

更新是唯一完整修复。下列措施只阻断已确认的攻击路径，不能替代补丁。

### 针对 CVE-2026-109618

- 以 FPM pool、Apache 配置等应用无法覆盖的方式设置并强制 `memory_limit=-1`。
- 保持较低的 `post_max_size`，并让 `upload_max_filesize` 小于它。
- 不需要上传的站点，在 nginx/Apache/反向代理层阻止 `multipart/form-data`。
- 在代理层限制解码后的请求大小、multipart part 数、header 数、字段数和嵌套深度。
- 不要用 `RLIMIT_AS` 或 `RLIMIT_DATA` 代替 PHP 限制，它们可能主动触发同一 OOM 路径。容器/cgroup 可作为可用性边界，但同样不是完整补丁。

### 针对 CVE-2026-109619

- 在请求初始化前生效的 PHP、FPM pool 或服务器配置中设置 `session.upload_progress.enabled=0`，然后重启全部 worker。
- PHP 8.5 同时设置 `fatal_error_backtraces=0`。
- 删除或修正会在请求初始化前产生 warning/notice/deprecation 的无效、过时或冲突 INI 设置。
- 不要依赖 `.user.ini` 或 `ini_set()` 完成这两个运行时缓解；它们对部分攻击路径生效太晚。

## 资产排查顺序

1. 互联网暴露的 Web 服务优先，`mod_php`、FrankenPHP 和内置 PHP 设备其次。
2. Linux 检查 PATH、`/www/server/php`、`/usr/local`、`/opt`、systemd/init、PHP-FPM pool、Apache 模块和 Docker。
3. Windows Server 检查 `PATH`、IIS FastCGI、Apache、XAMPP/WAMP/Laragon、Windows 服务命令行、注册表和 `php.exe`/`php-cgi.exe`。
4. 第三方产品、NAS、监控、控制面板、邮件系统与容器镜像要查厂商公告；主机 PHP 升级不会自动替换产品内嵌运行时。
5. 核对实际 Web SAPI，而不只看 `php -v`。同一台机器可能同时存在 CLI、FPM、CGI、mod_php 和多个旧目录。
6. 对比软件包安装时间与 PHP 进程启动时间。升级后未重启时，旧 worker 仍可能执行旧代码。

## 生产修复顺序

1. **先快照**。在云厂商或虚拟化平台创建整机快照；脚本内备份只覆盖它管理的 PHP 文件。
2. 记录 `php -v`、`php -i`、SAPI、FPM pool、Apache 模块、扩展列表、系统包版本、容器镜像 ID 和服务状态。
3. 备份 `php.ini`、FPM/Apache 配置、扩展文件和现有二进制。
4. 选择同分支官方修复版，或接入已在官方公告中确认修复的发行版软件包。
5. 在维护窗口停止接收新流量，或通过负载均衡摘除节点。
6. 安装更新并运行配置检查。Docker 必须拉取新镜像并重建容器，不能只执行 `docker restart`。
7. 完整重启 PHP-FPM、Apache/mod_php、IIS/W3SVC、LiteSpeed/FrankenPHP 及所有长驻 PHP worker。
8. 验证 `php -v`、实际 Web SAPI、登录、上传、支付、队列、计划任务、缓存和关键 API。
9. 保留旧版本与回滚脚本至少到稳定观察期结束。
10. 如果修复前曾暴露在互联网，保留日志并排查 webshell、异常子进程、新账号、新 cron/计划任务、异常外连和凭据读取。

## Linux 回滚

首选回滚仍是云厂商整机快照。组件级回滚命令会在工作目录内生成：

```bash
ls -l /root/php2shell-fullfix/latest
bash /root/php2shell-fullfix/<时间戳>/rollback.sh
```

执行前先查看 `report.txt`、`plan.txt` 和 `rollback.sh`，确认回滚目标和当前服务一致。宝塔源码 PHP 与 Debian 官方镜像容器的备份清单分别记录在 `bt-backups.tsv`、`docker-backups.tsv`。

## Windows Server 回滚

脚本必须放到实际运行 PHP 的 Windows Server/NT 服务器本机执行，普通工作站的 `-Apply` 会被拒绝。

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File "C:\ProgramData\PHP2ShellFullFix\<时间戳>\rollback.ps1"
```

回滚前确认备份清单、原服务状态和 `php.ini` 未被其他运维操作再次修改。PHP 7.4/8.0/8.1 没有对应官方 Windows 安全 ZIP，脚本不会伪造版本；应升级到受支持分支，或使用厂商/源码回溯补丁。

## 工具边界

- HTTP 扫描是无害指纹检查，不发送利用载荷，也无法证明隐藏版本的站点安全。
- 远程批量盘点主要面向 Linux + OpenSSH；Windows Server 使用本机 PowerShell 全流程脚本。
- 全流程脚本默认只检查。自动修复仅覆盖能够验证模式的宝塔 PHP、限定 Debian PHP 官方镜像容器和 Windows 官方 PHP ZIP 安装。
- 发行版包、未知源码构建、第三方控制面板和嵌入式运行时只给路径，不做盲改。

## 香港生产节点复核记录

2026-10-22 的授权复核中，生产节点上的 `/www/server/php/84` CLI、PHP-FPM 与 CGI 均为 8.4.27；Nextcloud `ocps/nextcloud:34.0.4-php8.5.12` 容器的 mod_php 为 8.5.12。PHP-FPM 已完整重启，扫描结果没有继续命中这两个 CVE。

本次结论只覆盖已盘点到的运行时。隐藏版本、第三方内嵌 PHP、之后新建的容器或其他服务器仍需分别核查。

## 主要来源

- PHP 官方安全公告：<https://www.php.net/archive/2026.php#2026-10-21-5>
- CVE-2026-109618 / GHSA-w8hw-w9fx-j79w：<https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w>
- CVE-2026-109619 / GHSA-6wmf-4rv5-p3rp：<https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp>
- PHP 8.2.35 发布记录：<https://github.com/php/php-src/releases/tag/php-8.2.35>
- NCSC-NL 操作信息：<https://github.com/NCSC-NL/php2shell>
- CISA CSAF/VEX：<https://vulnerability.circl.lu/vuln/VA-26-295-01>
- Canadian Centre for Cyber Security AL26-026：<https://www.cyber.gc.ca/en/alerts-advisories/al26-026-critical-vulnerabilities-impacting-php-cve-2026-109618-cve-2026-109619>
- CERT-EU 2026-018：<https://cert.europa.eu/publications/security-advisories/2026-018/>
- Cloudflare WAF 说明：<https://blog.cloudflare.com/php-vulnerabilities-waf-protection>
