from __future__ import annotations

import concurrent.futures
import csv
import io
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterable

from .remote_audit import REMOTE_AUDIT_SCRIPT

CVE_IDS = ("CVE-2026-109618", "CVE-2026-109619")
FIXED_VERSIONS = {
    "8.5": "8.5.12",
    "8.4": "8.4.27",
    "8.3": "8.3.36",
    "8.2": "8.2.35",
}
_VERSION_RE = re.compile(r"\bPHP(?:/|\s+)(\d+\.\d+\.\d+)\b", re.IGNORECASE)
_SERVER_VERSION_RE = re.compile(r"\bPHP/(\d+\.\d+\.\d+)\b", re.IGNORECASE)
_HOST_RE = re.compile(r"^[A-Za-z0-9_.:\[\]-]+$")
_USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _version_tuple(version: str) -> tuple[int, int, int]:
    major, minor, patch = version.split(".", 2)
    return int(major), int(minor), int(patch)


def extract_php_version(text: str) -> str | None:
    if not text:
        return None
    match = _VERSION_RE.search(text) or _SERVER_VERSION_RE.search(text)
    return match.group(1) if match else None


def classify_php_version(version: str | None) -> dict[str, Any]:
    """Classify a PHP version against the two disclosed RCE advisories."""
    result: dict[str, Any] = {
        "version": version,
        "branch": None,
        "status": "unknown",
        "fixed_version": None,
        "cves": [],
        "reason": "未识别到 PHP 版本",
    }
    if not version:
        return result
    try:
        major, minor, patch = _version_tuple(version)
    except (ValueError, TypeError):
        return result

    branch = f"{major}.{minor}"
    result["branch"] = branch
    fixed = FIXED_VERSIONS.get(branch)
    if fixed:
        result["fixed_version"] = fixed
        if (major, minor, patch) < _version_tuple(fixed):
            result.update(
                status="vulnerable",
                cves=list(CVE_IDS),
                reason=f"PHP {branch} 分支低于修复版本 {fixed}",
            )
        else:
            result.update(
                status="fixed",
                reason=f"已达到 {branch} 分支修复版本 {fixed}",
            )
        return result

    if major < 8 or (major == 8 and minor < 2):
        result.update(
            status="eol",
            cves=list(CVE_IDS),
            reason="PHP 已停止上游安全维护；应按可能受影响处理，升级到受支持分支或使用厂商回溯补丁",
        )
    elif major == 8 and minor == 6:
        result.update(
            status="review",
            reason="PHP 8.6 尚处于 RC 阶段，未获官方稳定版修复承诺；请改用受支持稳定分支或人工复核",
        )
    else:
        result.update(status="review", reason="不在官方稳定分支修复表中，需要人工复核")
    return result


def _extract_sapi(raw: str) -> str:
    match = re.search(r"\(([^)]+)\)", raw or "")
    return match.group(1) if match else "unknown"


def _clean_error(text: str, limit: int = 800) -> str:
    text = (text or "").replace("\x00", "").strip()
    text = re.sub(r"(?i)(password|secret|token|private key)\s*[:=]\s*\S+", r"\1=[REDACTED]", text)
    text = re.sub(
        r"(?i)(--?(?:password|passwd|secret|token|key|api[-_]?key)(?:=|\s+))\S+",
        r"\1[REDACTED]",
        text,
    )
    text = re.sub(r"(?i)([?&](?:token|key|secret|password|signature)=)[^&\s]+", r"\1[REDACTED]", text)
    return text[:limit]


def _sanitize_header_value(name: str, value: str) -> str:
    if name.lower() in {"set-cookie", "cookie", "authorization", "proxy-authorization"}:
        return "[REDACTED]"
    return _clean_error(value, 500)


def _redacted_url(url: str) -> str:
    try:
        parts = urllib.parse.urlsplit(url)
        hostname = parts.hostname or ""
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"
        netloc = hostname
        if parts.port:
            netloc += f":{parts.port}"
        return urllib.parse.urlunsplit((parts.scheme, netloc, parts.path, "", ""))
    except Exception:
        return _clean_error(url, 300)


@dataclass
class ServerSpec:
    name: str
    host: str
    port: int = 22
    user: str = "root"
    key_path: str = ""


@dataclass
class TargetSpec:
    name: str
    url: str


@dataclass
class ScanConfig:
    timeout_sec: int = 25
    workers: int = 8
    default_key_path: str = ""
    verify_tls: bool = True
    known_hosts_path: str = ""

    def normalized(self) -> "ScanConfig":
        return ScanConfig(
            timeout_sec=max(5, min(int(self.timeout_sec), 180)),
            workers=max(1, min(int(self.workers), 64)),
            default_key_path=os.path.expanduser(self.default_key_path or ""),
            verify_tls=bool(self.verify_tls),
            known_hosts_path=os.path.expanduser(self.known_hosts_path or ""),
        )


@dataclass
class ScanJob:
    servers: list[ServerSpec] = field(default_factory=list)
    targets: list[TargetSpec] = field(default_factory=list)
    config: ScanConfig = field(default_factory=ScanConfig)


def _looks_like_header(row: list[str]) -> bool:
    normalized = {x.strip().lower() for x in row}
    return "host" in normalized and bool({"name", "port", "user", "key"} & normalized)


def _parse_server_fields(fields: list[str]) -> ServerSpec:
    fields = [x.strip() for x in fields]
    if len(fields) == 1:
        return _parse_server_shorthand(fields[0])
    while len(fields) < 5:
        fields.append("")
    name, host, port, user, key_path = fields[:5]
    if not name:
        name = host
    if not host:
        raise ValueError("服务器地址为空")
    if not _HOST_RE.fullmatch(host) or host.startswith("-"):
        raise ValueError(f"服务器地址不合法: {host!r}")
    if not _USER_RE.fullmatch(user or "root"):
        raise ValueError(f"SSH 用户不合法: {user!r}")
    try:
        port_number = int(port or "22")
    except ValueError as exc:
        raise ValueError(f"端口不是数字: {port!r}") from exc
    if not 1 <= port_number <= 65535:
        raise ValueError(f"端口越界: {port_number}")
    return ServerSpec(
        name=name,
        host=host,
        port=port_number,
        user=user or "root",
        key_path=key_path,
    )


def _parse_server_shorthand(value: str) -> ServerSpec:
    value = value.strip()
    if not value:
        raise ValueError("服务器地址为空")
    user = "root"
    if "@" in value:
        user, value = value.rsplit("@", 1)
    host = value
    port = 22
    if value.startswith("[") and "]" in value:
        end = value.index("]")
        host = value[1:end]
        rest = value[end + 1 :]
        if rest.startswith(":") and rest[1:]:
            port = int(rest[1:])
    else:
        colon_count = value.count(":")
        if colon_count == 1:
            host, port_text = value.rsplit(":", 1)
            if port_text.isdigit():
                port = int(port_text)
    return _parse_server_fields([host, host, str(port), user, ""])


def parse_server_text(text: str) -> tuple[list[ServerSpec], list[str]]:
    servers: list[ServerSpec] = []
    errors: list[str] = []
    header_seen = False
    for line_number, raw_line in enumerate((text or "").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            if "\t" in line:
                fields = line.split("\t")
            elif "|" in line:
                fields = line.split("|")
            else:
                fields = next(csv.reader(io.StringIO(line)))
            if _looks_like_header(fields) and not header_seen:
                header_seen = True
                continue
            servers.append(_parse_server_fields(fields))
        except Exception as exc:
            errors.append(f"服务器第 {line_number} 行: {exc}")
    return servers, errors


def parse_target_text(text: str) -> tuple[list[TargetSpec], list[str]]:
    targets: list[TargetSpec] = []
    errors: list[str] = []
    for line_number, raw_line in enumerate((text or "").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        name = ""
        url = line
        if "|" in line:
            maybe_name, maybe_url = line.split("|", 1)
            if maybe_url.strip().lower().startswith(("http://", "https://")):
                name, url = maybe_name.strip(), maybe_url.strip()
            else:
                url = maybe_url.strip()
        if not url.lower().startswith(("http://", "https://")):
            url = "https://" + url
        try:
            parsed = urllib.parse.urlsplit(url)
        except ValueError:
            errors.append(f"目标第 {line_number} 行: URL 不合法")
            continue
        hostname = parsed.hostname or ""
        if (
            parsed.scheme not in {"http", "https"}
            or not hostname
            or any(char.isspace() or ord(char) < 32 for char in hostname)
        ):
            errors.append(f"目标第 {line_number} 行: URL 不合法")
            continue
        targets.append(TargetSpec(name=name or parsed.hostname, url=url))
    return targets, errors


def _parse_setting_line(line: str) -> tuple[str, str]:
    value = line.split(" => ", 1)[0]
    if " => " in line:
        parts = line.split(" => ")
        value = parts[1].strip() if len(parts) > 1 else parts[0].strip()
        key = parts[0].strip()
    else:
        key = line.split("=", 1)[0].strip()
        value = line.split("=", 1)[1].strip() if "=" in line else ""
    return key, value


def parse_remote_audit_output(output: str) -> dict[str, Any]:
    parsed: dict[str, Any] = {
        "meta": {},
        "bins": [],
        "settings": {},
        "docker_settings": {},
        "services": [],
        "processes": [],
        "apache_modules": [],
        "docker_apache_modules": {},
        "packages": [],
        "pool_settings": [],
        "docker_php": [],
    }
    bin_map: dict[str, dict[str, Any]] = {}
    for raw_line in (output or "").splitlines():
        if "\t" not in raw_line:
            continue
        kind, payload = raw_line.split("\t", 1)
        if kind == "META" and "=" in payload:
            key, value = payload.split("=", 1)
            parsed["meta"][key] = value
        elif kind == "BIN":
            parts = payload.split("|", 2)
            if len(parts) != 3:
                continue
            path, binary_kind, first_line = parts
            version = extract_php_version(first_line)
            entry = bin_map.setdefault(
                path,
                {
                    "path": path,
                    "kind": binary_kind,
                    "raw": first_line,
                    "version": version,
                    "sapi": _extract_sapi(first_line),
                    "config": {},
                },
            )
            if version:
                entry["version"] = version
        elif kind == "SETTING" and "|" in payload:
            path, setting = payload.split("|", 1)
            key, value = _parse_setting_line(setting)
            bin_map.setdefault(path, {"path": path, "kind": "php", "raw": "", "version": None, "sapi": "unknown", "config": {}})
            bin_map[path]["config"][key] = value
        elif kind == "DOCKER_PHP":
            parts = payload.split("|", 2)
            if len(parts) != 3:
                continue
            container, image, first_line = parts
            parsed["docker_php"].append(
                {
                    "path": f"docker:{container}",
                    "container": container,
                    "image": image,
                    "kind": "docker",
                    "raw": first_line,
                    "version": extract_php_version(first_line),
                    "sapi": _extract_sapi(first_line),
                    "config": {},
                }
            )
        elif kind == "DOCKER_SETTING" and "|" in payload:
            container, setting = payload.split("|", 1)
            key, value = _parse_setting_line(setting)
            parsed["docker_settings"].setdefault(container, {})[key] = value
        elif kind == "DOCKER_APACHE_MODULE" and "|" in payload:
            container, module = payload.split("|", 1)
            parsed["docker_apache_modules"].setdefault(container, []).append(module)
        elif kind == "SERVICE":
            parsed["services"].append(payload)
        elif kind == "PROCESS":
            parsed["processes"].append(payload)
        elif kind == "APACHE_MODULE":
            parsed["apache_modules"].append(payload)
        elif kind == "PACKAGE":
            parsed["packages"].append(payload)
        elif kind == "POOL_SETTING":
            parsed["pool_settings"].append(payload)
    parsed["bins"] = list(bin_map.values())
    for item in parsed["docker_php"]:
        item["config"] = parsed["docker_settings"].get(item["container"], {})
        modules = parsed["docker_apache_modules"].get(item["container"], [])
        if any("php_module" in module or "php7_module" in module for module in modules):
            item["sapi"] = "apache2handler (mod_php)"
            item["web_sapi_confirmed"] = True
    return parsed


def _status_from_runtimes(runtimes: list[dict[str, Any]], had_php_hint: bool = False) -> tuple[str, list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    if not runtimes:
        return ("unknown" if had_php_hint else "no_php"), findings
    states: list[str] = []
    for runtime in runtimes:
        classification = classify_php_version(runtime.get("version"))
        states.append(classification["status"])
        runtime["classification"] = classification
        if classification["status"] in {"vulnerable", "eol"}:
            findings.append(
                {
                    "cves": classification["cves"],
                    "severity": "critical" if classification["status"] == "vulnerable" else "eol",
                    "version": runtime.get("version"),
                    "runtime": runtime.get("path"),
                    "reason": classification["reason"],
                }
            )
    if "vulnerable" in states:
        return "vulnerable", findings
    if "eol" in states:
        return "at_risk", findings
    if "review" in states or "unknown" in states:
        return "unknown", findings
    return "fixed", findings


def _fix_for_runtime(runtime: dict[str, Any], status: str) -> list[dict[str, Any]]:
    classification = runtime.get("classification") or classify_php_version(runtime.get("version"))
    version = runtime.get("version")
    path = runtime.get("path", "")
    fixed = classification.get("fixed_version")
    kind = runtime.get("kind", "")
    fixes: list[dict[str, Any]] = []
    if classification["status"] == "fixed":
        fixes.append(
            {
                "title": "该运行时已修复",
                "steps": [
                    "确认 Web 服务实际使用该二进制，而不是另一个残留 PHP 版本。",
                    "升级后执行完整服务重启；PHP-FPM 不要只 reload 旧 master。",
                    "从真实 Web 入口验证版本、上传、登录和关键业务。",
                ],
            }
        )
        return fixes
    if classification["status"] in {"eol", "review"}:
        fixes.append(
            {
                "title": "升级到受支持的稳定分支",
                "steps": [
                    "优先升级到 PHP 8.4.27 或 8.5.12；PHP 8.2 将于 2026-12-31 EOL。",
                    "若不能立即升级，向发行版/LTS 厂商取得明确包含两个 CVE 的回溯补丁。",
                    "PHP 7.4、8.0、8.1 可能需要官方提供的源码回溯补丁，不能只改配置。",
                ],
            }
        )
        return fixes
    if kind == "docker" or path.startswith("docker:"):
        container = runtime.get("container", path.split(":", 1)[-1])
        image = runtime.get("image", "当前镜像")
        fixes.append(
            {
                "title": f"更新容器 {container} 的 PHP 运行时",
                "steps": [
                    f"当前镜像：{image}。把镜像更新到包含 PHP {fixed} 的版本。",
                    "不要只执行 docker restart；需要拉取/构建新镜像并重建容器。",
                    "容器重建前保留镜像 digest、数据卷和数据库备份。",
                    f"重建后执行：docker exec {container} php -v；再从 Web 入口做健康检查。",
                ],
            }
        )
        return fixes
    if path.startswith("/www/server/php/"):
        prefix = str(Path(path).parents[1]) if path.count("/") >= 4 else "/www/server/php"
        archive = f"php-{fixed}.tar.xz"
        fixes.append(
            {
                "title": f"源码安装路径升级到 PHP {fixed}",
                "steps": [
                    f"先完整备份 {prefix}，并记录当前二进制 SHA-256。",
                    f"从 https://www.php.net/distributions/{archive} 下载并核对官方 SHA-256。",
                    "使用现有的同一组 configure 参数编译；先验证 CLI、FPM 配置和扩展，再替换运行文件。",
                    "停止 PHP-FPM，执行 make install，运行 php-fpm -t，再完整启动服务。",
                    "验证 php -v、php-fpm -v、OPcache 版本和真实 Web 入口。",
                ],
            }
        )
        return fixes
    fixes.append(
        {
            "title": f"升级到 PHP {fixed}",
            "steps": [
                "优先使用发行版或托管商提供的安全包；在 CVE 跟踪页确认状态为 Fixed 后再安装。",
                "源码安装时从 php.net 下载对应修复版本，保留旧 prefix/二进制用于回滚。",
                "升级后完整重启 FPM/Apache/LiteSpeed/FrankenPHP，并验证真实 Web SAPI。",
            ],
        }
    )
    return fixes


def _fallback_fixes(status: str) -> list[dict[str, Any]]:
    if status == "unknown":
        return [
            {
                "title": "无法用当前证据确认版本",
                "steps": [
                    "HTTP 头隐藏 PHP 版本时，不能用“看不到版本”推断安全。",
                    "改用 SSH 模式扫描主机、容器和控制面板，确认实际 PHP-FPM/mod_php 运行时。",
                    "同时检查反向代理、CDN、systemd、Docker 和共享主机控制面板。",
                ],
            }
        ]
    if status == "error":
        return [
            {
                "title": "扫描未完成",
                "steps": [
                    "确认主机、端口、SSH 用户和私钥正确，并在本机先测试一次交互式 SSH 登录。",
                    "检查安全组、防火墙、fail2ban 和 known_hosts；主机指纹变化时应人工核实。",
                    "修复连接后重新扫描，不要把连接失败视为服务器安全。",
                ],
            }
        ]
    if status == "no_php":
        return [
            {
                "title": "未发现 PHP 指纹",
                "steps": [
                    "如果该目标确实运行 PHP，使用 SSH 模式确认版本；反向代理可能隐藏响应头。",
                    "检查独立子域、后台、API、预览环境、共享主机和 Docker 容器。",
                ],
            }
        ]
    return []


def _temporary_mitigation_fix() -> dict[str, Any]:
    return {
        "title": "无法立即补丁时的临时降低风险措施（不完整）",
        "steps": [
            "把 session.upload_progress.enabled 设为 Off，写入 php.ini/FPM/Apache 启动配置，并完整重启所有 worker。",
            "PHP 8.5 可同时设置 fatal_error_backtraces=0；它会关闭已确认的一条利用路径，但不是完整修复。",
            "如有必要，管理层面短时设置 memory_limit=-1，确认应用和 pool 无法覆盖；这会增加内存耗尽风险。",
            "收紧 post_max_size，并在 Nginx/WAF/代理层限制 multipart 部件、header、嵌套、上传数量和总请求大小。",
            "敏感系统在无法及时补丁时应限制公网访问或暂时下线。WAF 只能作过渡，不能替代升级。",
        ],
    }


def _result_from_audit(server: ServerSpec, parsed: dict[str, Any]) -> dict[str, Any]:
    runtimes = list(parsed.get("bins", [])) + list(parsed.get("docker_php", []))
    package_hint = any("php" in x.lower() for x in parsed.get("packages", []))
    status, findings = _status_from_runtimes(runtimes, package_hint)
    fixes: list[dict[str, Any]] = []
    for runtime in runtimes:
        fixes.extend(_fix_for_runtime(runtime, status))
    if status in {"vulnerable", "at_risk"}:
        fixes.append(_temporary_mitigation_fix())
    if not fixes:
        fixes.extend(_fallback_fixes(status))
    processes = [_clean_error(item, 500) for item in parsed.get("processes", [])]
    meta = parsed.get("meta", {})
    return {
        "id": f"ssh:{server.name}:{server.host}:{server.port}",
        "mode": "ssh",
        "name": server.name,
        "target": f"{server.user}@{server.host}:{server.port}",
        "address": f"{server.user}@{server.host}:{server.port}",
        "status": status,
        "scanned_at": now_iso(),
        "hostname": meta.get("host", server.name),
        "os": meta.get("os", meta.get("kernel", "")),
        "php_runtimes": runtimes,
        "findings": findings,
        "evidence": {
            "services": parsed.get("services", []),
            "processes": processes,
            "apache_modules": parsed.get("apache_modules", []),
            "docker_apache_modules": parsed.get("docker_apache_modules", {}),
            "packages": parsed.get("packages", []),
            "pool_settings": parsed.get("pool_settings", []),
        },
        "fixes": fixes,
        "errors": [],
    }


def _find_ssh() -> str:
    ssh = shutil.which("ssh")
    if not ssh:
        raise RuntimeError("未找到 OpenSSH 客户端（ssh）")
    return ssh


def scan_ssh_server(server: ServerSpec, config: ScanConfig) -> dict[str, Any]:
    started = time.monotonic()
    key_path = os.path.expanduser(server.key_path or config.default_key_path or "")
    key_args: list[str] = []
    if key_path:
        if not Path(key_path).is_file():
            return _error_result(server, f"SSH 私钥不存在: {key_path}", started)
        key_args = ["-i", key_path, "-o", "IdentitiesOnly=yes"]
    known_hosts = config.known_hosts_path or str(Path.home() / ".ssh" / "known_hosts")
    Path(known_hosts).parent.mkdir(parents=True, exist_ok=True)
    args = [
        _find_ssh(),
        *key_args,
        "-p",
        str(server.port),
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={max(5, min(config.timeout_sec, 20))}",
        "-o",
        "ServerAliveInterval=5",
        "-o",
        "ServerAliveCountMax=2",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        f"UserKnownHostsFile={known_hosts}",
        "-o",
        "UpdateHostKeys=yes",
        "-o",
        "LogLevel=ERROR",
        f"{server.user}@{server.host}",
        "sh -s",
    ]
    try:
        proc = subprocess.run(
            args,
            input=REMOTE_AUDIT_SCRIPT.replace("\r\n", "\n").encode("utf-8"),
            capture_output=True,
            timeout=config.timeout_sec + 25,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return _error_result(server, "SSH 检查超时", started)
    except Exception as exc:
        return _error_result(server, f"SSH 检查失败: {_clean_error(str(exc))}", started)
    stdout = proc.stdout.decode("utf-8", errors="replace")
    stderr = proc.stderr.decode("utf-8", errors="replace")
    parsed = parse_remote_audit_output(stdout)
    if proc.returncode != 0 and not parsed.get("bins") and not parsed.get("docker_php"):
        detail = _clean_error(stderr) or f"ssh 退出码 {proc.returncode}"
        return _error_result(server, detail, started)
    result = _result_from_audit(server, parsed)
    result["duration_sec"] = round(time.monotonic() - started, 2)
    if stderr.strip():
        result["errors"].append(_clean_error(stderr, 400))
    return result


def _error_result(server: ServerSpec, error: str, started: float | None = None) -> dict[str, Any]:
    return {
        "id": f"ssh:{server.name}:{server.host}:{server.port}",
        "mode": "ssh",
        "name": server.name,
        "target": f"{server.user}@{server.host}:{server.port}",
        "address": f"{server.user}@{server.host}:{server.port}",
        "status": "error",
        "scanned_at": now_iso(),
        "hostname": server.name,
        "os": "",
        "php_runtimes": [],
        "findings": [],
        "evidence": {},
        "fixes": _fallback_fixes("error"),
        "errors": [error],
        "duration_sec": round(time.monotonic() - started, 2) if started is not None else 0,
    }


class _LimitedRedirect(urllib.request.HTTPRedirectHandler):
    max_redirections = 3


def scan_http_target(target: TargetSpec, config: ScanConfig) -> dict[str, Any]:
    started = time.monotonic()
    display_url = _redacted_url(target.url)
    headers: dict[str, str] = {}
    body = b""
    status_code = 0
    final_url = target.url
    error = ""
    context = ssl.create_default_context()
    if not config.verify_tls:
        context = ssl._create_unverified_context()
    opener = urllib.request.build_opener(_LimitedRedirect(), urllib.request.HTTPSHandler(context=context))
    request = urllib.request.Request(
        target.url,
        headers={
            "User-Agent": "PHP2ShellScanner/1.0 (safe version fingerprint)",
            "Accept": "text/html,application/xhtml+xml",
            "Cache-Control": "no-cache",
        },
        method="GET",
    )
    try:
        with opener.open(request, timeout=config.timeout_sec) as response:
            status_code = response.status
            final_url = response.geturl()
            headers = {k: v for k, v in response.headers.items()}
            body = response.read(65536)
    except urllib.error.HTTPError as exc:
        status_code = exc.code
        final_url = exc.geturl()
        headers = {k: v for k, v in exc.headers.items()}
        body = exc.read(65536)
    except Exception as exc:
        error = _clean_error(f"HTTP 检查失败: {exc}")

    fingerprints = []
    for header_name in ("X-Powered-By", "Server", "Via"):
        for key, value in headers.items():
            if key.lower() == header_name.lower():
                fingerprints.append(f"{key}: {value}")
    version = None
    for line in fingerprints:
        version = extract_php_version(line)
        if version:
            break
    php_hint = any("phpsessid" in value.lower() for value in headers.values())
    runtimes: list[dict[str, Any]] = []
    if version or php_hint:
        runtimes.append(
            {
                "path": display_url,
                "kind": "http",
                "raw": next((x for x in fingerprints if "php" in x.lower()), "PHPSESSID present" if php_hint else ""),
                "version": version,
                "sapi": "web",
                "config": {},
            }
        )
    # A web response cannot prove PHP is absent; hidden headers are common.
    status, findings = _status_from_runtimes(runtimes, True)
    if error:
        status = "error"
    fixes = []
    for runtime in runtimes:
        fixes.extend(_fix_for_runtime(runtime, status))
    if status in {"vulnerable", "at_risk"}:
        fixes.append(_temporary_mitigation_fix())
    if not fixes:
        fixes.extend(_fallback_fixes(status))
    result = {
        "id": f"http:{display_url}",
        "mode": "http",
        "name": target.name,
        "target": display_url,
        "address": urllib.parse.urlsplit(target.url).hostname or target.name,
        "status": status,
        "scanned_at": now_iso(),
        "hostname": urllib.parse.urlsplit(final_url).hostname or target.name,
        "os": "",
        "php_runtimes": runtimes,
        "findings": findings,
        "evidence": {
            "http_status": status_code,
            "final_url": _redacted_url(final_url),
            "headers": {
                name: _sanitize_header_value(name, value)
                for name, value in headers.items()
                if name.lower()
                in {
                    "server",
                    "x-powered-by",
                    "via",
                    "content-type",
                    "cache-control",
                    "x-nextcloud-version",
                }
            },
            "set_cookie_present": "set-cookie" in {name.lower() for name in headers},
            "fingerprints": fingerprints,
        },
        "fixes": fixes,
        "errors": [error] if error else [],
        "duration_sec": round(time.monotonic() - started, 2),
    }
    return result


def summarize_results(results: Iterable[dict[str, Any]]) -> dict[str, int]:
    summary = {
        "total": 0,
        "vulnerable": 0,
        "at_risk": 0,
        "unknown": 0,
        "fixed": 0,
        "no_php": 0,
        "error": 0,
    }
    for result in results:
        summary["total"] += 1
        status = result.get("status", "error")
        summary[status] = summary.get(status, 0) + 1
    return summary


def scan_job(
    servers: list[ServerSpec],
    targets: list[TargetSpec],
    config: ScanConfig,
    on_result: Callable[[dict[str, Any]], None] | None = None,
    on_progress: Callable[[int, int], None] | None = None,
) -> dict[str, Any]:
    config = config.normalized()
    jobs: list[tuple[str, Any]] = [("ssh", x) for x in servers] + [("http", x) for x in targets]
    total = len(jobs)
    results: list[dict[str, Any]] = []
    if total == 0:
        raise ValueError("请至少提供一台 SSH 服务器或一个 HTTP 目标")

    def run_one(kind: str, item: Any) -> dict[str, Any]:
        if kind == "ssh":
            return scan_ssh_server(item, config)
        return scan_http_target(item, config)

    completed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=config.workers) as pool:
        future_map = {pool.submit(run_one, kind, item): (kind, item) for kind, item in jobs}
        for future in concurrent.futures.as_completed(future_map):
            kind, item = future_map[future]
            try:
                result = future.result()
            except Exception as exc:
                if kind == "ssh":
                    result = _error_result(item, f"扫描异常: {_clean_error(str(exc))}")
                else:
                    result = scan_http_target(item, config)
                    result["status"] = "error"
                    result["errors"].append(_clean_error(str(exc)))
            results.append(result)
            completed += 1
            if on_result:
                on_result(result)
            if on_progress:
                on_progress(completed, total)
    results.sort(key=lambda x: (x.get("status") != "vulnerable", x.get("name", "")))
    return {
        "scanner": "PHP2Shell Scanner",
        "scanner_version": "1.0.2",
        "scanned_at": now_iso(),
        "cves": list(CVE_IDS),
        "fixed_versions": dict(FIXED_VERSIONS),
        "summary": summarize_results(results),
        "results": results,
    }


def self_test() -> None:
    assert classify_php_version("8.4.23")["status"] == "vulnerable"
    assert classify_php_version("8.4.27")["status"] == "fixed"
    assert classify_php_version("8.5.11")["status"] == "vulnerable"
    assert classify_php_version("8.5.12")["status"] == "fixed"
    assert classify_php_version("8.3.35")["status"] == "vulnerable"
    assert classify_php_version("8.2.35")["status"] == "fixed"
    assert classify_php_version("7.4.33")["status"] == "eol"
    assert extract_php_version("PHP 8.4.23 (cli)") == "8.4.23"
    servers, errors = parse_server_text("name,host,port,user,key\ndemo,192.0.2.50,2222,deploy,\n")
    assert not errors and servers[0].host == "192.0.2.50"
    parsed = parse_remote_audit_output(
        "META\thost=test\nBIN\t/www/server/php/84/sbin/php-fpm|fpm|PHP 8.4.23 (fpm-fcgi)\n"
    )
    assert parsed["bins"][0]["version"] == "8.4.23"
