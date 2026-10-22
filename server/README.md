# PHP2Shell 服务器端全流程脚本

这两个脚本用于直接在服务器上检查并修复：

- `CVE-2026-109618`
- `CVE-2026-109619`

默认都只检查，不会修改系统。

## 必须先做整机快照

脚本内的备份只覆盖它管理的 PHP 目录和服务，不包含数据库、网站代码、队列数据或其他系统组件。

执行修复前，请先在云厂商或虚拟化平台创建整机快照。脚本会要求连续输入三次确认口令。

## Linux

文件：

```text
php2shell-fullfix-linux.sh
```

要求：Linux、Bash 4+、root 权限、标准 coreutils/tar/curl。

上传到服务器后检查：

```bash
chmod 700 php2shell-fullfix-linux.sh
sudo bash php2shell-fullfix-linux.sh --check
```

检查模式不会重启服务或修改 PHP。

确认快照和回滚方式后执行：

```bash
sudo bash php2shell-fullfix-linux.sh --apply \
  --http-url https://soundlibs.com/ \
  --http-url https://stocklibs.com/
```

可选参数：

```text
--skip-bt                 不处理宝塔 PHP
--skip-docker             不检查/处理 Docker
--stop-unfixable          修复模式下停止无法安全自动修复的受影响容器
--http-url URL            可重复；升级后做 HTTP 健康检查
```

### Linux 自动修复范围

1. 宝塔标准 PHP：`/www/server/php/74`、`80`、`81`、`82`、`83`、`84`、`85`
   - 下载并校验宝塔官方 `php.sh`
   - 使用宝塔官方编译升级流程
   - 修复版本：
     - 7.4.34
     - 8.0.27
     - 8.1.35
     - 8.2.35
     - 8.3.36
     - 8.4.27
     - 8.5.12
2. Debian 系官方 PHP 镜像或从中派生的 Docker 容器
   - 仅当 PHP 位于 `/usr/local/bin/php`
   - 容器系统为 Debian 12/13
   - 使用同分支官方修复镜像中的 PHP 核心、PHP-FPM 或 Apache `libphp.so`
   - 复制前提交容器镜像备份，并备份旧二进制
   - 替换前停止容器，失败时自动恢复旧文件

发行版 `apt/dnf` PHP 包、非宝塔源码目录及非标准容器会被识别，但默认不会盲改；脚本会给出人工修复路径。

### Linux 备份和回滚

工作目录：

```text
/root/php2shell-fullfix/<时间戳>/
```

重要文件：

```text
report.txt
plan.txt
rollback.sh
bt-backups.tsv
docker-backups.tsv
run.log
```

手动回滚：

```bash
bash /root/php2shell-fullfix/<时间戳>/rollback.sh
```

优先回滚方式仍是云厂商整机快照。

## Windows Server / Windows NT（服务器本机执行）

文件：

```text
php2shell-fullfix-windows.ps1
run-windows-server-fullfix.cmd
```

要求：Windows PowerShell 5.1 或更高版本；修复模式必须使用管理员 PowerShell。

**重要：这个 Windows 版本不是“在个人 PC 上扫描”。**
应把文件放到实际运行 PHP 的 Windows Server / Windows NT 服务器上，在服务器本机以管理员执行。普通 Windows 工作站只能运行检查模式，`-Apply` 会被脚本拒绝。

无 PowerShell 环境时，可以先双击或以管理员运行：

```bat
run-windows-server-fullfix.cmd
```

默认仍是只检查。自修服务器上的 Windows Server 2008 R2 或更早系统无法运行现代 PHP 8.2+，脚本会拒绝自动修复并提示迁移。

检查模式：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\php2shell-fullfix-windows.ps1 -Check
```

只检查指定 PHP 目录：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\php2shell-fullfix-windows.ps1 -Check `
  -OnlyPath "C:\php"
```

修复必须以管理员 PowerShell 运行：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\php2shell-fullfix-windows.ps1 -Apply `
  -HttpUrl "https://example.com/"
```

### Windows 自动修复范围

- PHP 8.2.x -> 8.2.35
- PHP 8.3.x -> 8.3.36
- PHP 8.4.x -> 8.4.27
- PHP 8.5.x -> 8.5.12

脚本会：

1. 从 `windows.php.net` 下载相同分支官方 ZIP。
2. 自动判断 NTS/ZTS、x64/x86 和 VS16/VS17。
3. 校验 `sha256sum.txt`。
4. 备份完整 PHP 安装目录。
5. 保存原有 `php.ini`。
6. 覆盖核心 EXE/DLL 和官方扩展 DLL，但保留额外第三方扩展文件。
7. 完整重启检测到的 PHP/Apache/IIS 相关服务。
8. 验证 CLI、php-cgi 和模块清单，并采样 OOM 行为作为辅助证据。

PHP 7.4、8.0、8.1 没有对应官方 Windows 安全修复 ZIP。脚本不会伪造修复版本，会要求升级到 PHP 8.4/8.5，或使用厂商/源码回溯补丁。

### Windows 备份和回滚

工作目录：

```text
C:\ProgramData\PHP2ShellFullFix\<时间戳>\
```

重要文件：

```text
report.txt
inventory.json
backup-manifest.json
rollback.ps1
backups\
```

手动回滚：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File "C:\ProgramData\PHP2ShellFullFix\<时间戳>\rollback.ps1"
```

如果检测到无法安全归类的 PHP CLI 后台进程，修复模式会停止并要求人工先停止这些进程，避免文件锁定或业务被静默中断。

## 三次确认

两个脚本在 `Apply` 模式都会要求：

1. `I_UNDERSTAND_THE_RISK`
2. `I_HAVE_A_FULL_SERVER_SNAPSHOT`
3. `I_HAVE_VERIFIED_THE_BACKUP_AND_ROLLBACK`

第三次确认发生在所有备份完成、精确回滚路径显示之后。
