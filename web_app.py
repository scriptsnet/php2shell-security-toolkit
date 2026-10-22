from __future__ import annotations

import argparse
import hmac
import json
import mimetypes
import os
import sys
import threading
import time
import uuid
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from php2shell.core import (
    ScanConfig,
    parse_server_text,
    parse_target_text,
    scan_job,
    self_test,
    summarize_results,
)
from php2shell.report import report_to_csv, report_to_html, report_to_json, report_to_markdown

APP_VERSION = "1.0.2"
ROOT = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))


def _locate_web_root() -> Path:
    candidates = [
        ROOT / "web",
        ROOT / "web" / "web",
        Path(__file__).resolve().parent / "web",
        Path(sys.executable).resolve().parent / "web",
    ]
    for candidate in candidates:
        if (candidate / "index.html").is_file():
            return candidate
    return candidates[0]


WEB_ROOT = _locate_web_root()


class JobStore:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.jobs: dict[str, dict] = {}

    def create(self, total: int) -> dict:
        job_id = uuid.uuid4().hex
        job = {
            "id": job_id,
            "state": "queued",
            "progress": 0,
            "total": total,
            "results": [],
            "report": None,
            "error": "",
            "created_at": time.time(),
        }
        with self.lock:
            self.jobs[job_id] = job
            self._cleanup_locked()
        return job

    def add_result(self, job_id: str, result: dict) -> None:
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                return
            job["results"].append(result)
            job["progress"] = len(job["results"])
            job["state"] = "running"

    def finish(self, job_id: str, report: dict) -> None:
        with self.lock:
            job = self.jobs.get(job_id)
            if job:
                job.update(state="done", report=report, progress=job["total"])

    def fail(self, job_id: str, error: str) -> None:
        with self.lock:
            job = self.jobs.get(job_id)
            if job:
                job.update(state="error", error=error)

    def snapshot(self, job_id: str) -> dict | None:
        with self.lock:
            job = self.jobs.get(job_id)
            if not job:
                return None
            payload = {
                "id": job["id"],
                "state": job["state"],
                "progress": job["progress"],
                "total": job["total"],
                "results": list(job["results"]),
                "summary": summarize_results(job["results"]) if job["results"] else {},
                "error": job["error"],
                "report": job["report"],
            }
            return payload

    def active_count(self) -> int:
        with self.lock:
            return sum(1 for job in self.jobs.values() if job["state"] in {"queued", "running"})

    def _cleanup_locked(self) -> None:
        cutoff = time.time() - 24 * 60 * 60
        stale = [key for key, value in self.jobs.items() if value["created_at"] < cutoff]
        for key in stale:
            self.jobs.pop(key, None)


STORE = JobStore()
API_TOKEN = ""


class ScannerHandler(BaseHTTPRequestHandler):
    server_version = "PHP2ShellScanner/1.0"

    def do_GET(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path == "/api/health":
            if not self._authorized(parsed):
                return
            self._json(
                {
                    "ok": True,
                    "version": APP_VERSION,
                    "cves": ["CVE-2026-109618", "CVE-2026-109619"],
                }
            )
            return
        if parsed.path.startswith("/api/jobs/"):
            if not self._authorized(parsed):
                return
            self._handle_job_get(parsed)
            return
        self._serve_static(parsed.path)

    def do_POST(self) -> None:
        parsed = urlsplit(self.path)
        if parsed.path != "/api/scan":
            self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
            return
        if not self._authorized(parsed):
            return
        if not self.headers.get("Content-Type", "").lower().startswith("application/json"):
            self._json({"error": "Content-Type must be application/json"}, HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > 1_000_000:
            self._json({"error": "请求体为空或过大"}, HTTPStatus.BAD_REQUEST)
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._json({"error": "JSON 格式不合法"}, HTTPStatus.BAD_REQUEST)
            return
        servers, server_errors = parse_server_text(str(payload.get("servers_text", "")))
        targets, target_errors = parse_target_text(str(payload.get("targets_text", "")))
        errors = server_errors + target_errors
        if errors:
            self._json({"error": "\n".join(errors[:30])}, HTTPStatus.BAD_REQUEST)
            return
        if not servers and not targets:
            self._json({"error": "请至少提供一台 SSH 服务器或一个 HTTP 目标"}, HTTPStatus.BAD_REQUEST)
            return
        total = len(servers) + len(targets)
        if total > 1000:
            self._json({"error": "单次任务最多 1000 个目标"}, HTTPStatus.BAD_REQUEST)
            return
        if STORE.active_count() >= 3:
            self._json({"error": "已有 3 个扫描任务在运行，请稍后重试"}, HTTPStatus.TOO_MANY_REQUESTS)
            return
        try:
            config = ScanConfig(
                timeout_sec=int(payload.get("timeout_sec", 25)),
                workers=int(payload.get("workers", 8)),
                default_key_path=str(payload.get("default_key_path", "")),
                verify_tls=bool(payload.get("verify_tls", True)),
            ).normalized()
        except (TypeError, ValueError):
            self._json({"error": "并发数和超时必须是整数"}, HTTPStatus.BAD_REQUEST)
            return
        job = STORE.create(total)

        def worker() -> None:
            try:
                report = scan_job(
                    servers,
                    targets,
                    config,
                    on_result=lambda result: STORE.add_result(job["id"], result),
                    on_progress=lambda done, total_count: None,
                )
                STORE.finish(job["id"], report)
            except Exception as exc:
                STORE.fail(job["id"], str(exc))

        threading.Thread(target=worker, daemon=True).start()
        self._json({"job_id": job["id"], "total": total}, HTTPStatus.ACCEPTED)

    def _handle_job_get(self, parsed) -> None:
        parts = parsed.path.strip("/").split("/")
        if len(parts) < 3:
            self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
            return
        job_id = parts[2]
        snapshot = STORE.snapshot(job_id)
        if snapshot is None:
            self._json({"error": "任务不存在或已过期"}, HTTPStatus.NOT_FOUND)
            return
        if len(parts) == 4 and parts[3] == "report":
            if not snapshot.get("report"):
                self._json({"error": "报告尚未完成"}, HTTPStatus.CONFLICT)
                return
            fmt = parse_qs(parsed.query).get("format", ["html"])[0].lower()
            report = snapshot["report"]
            if fmt == "json":
                self._send_bytes(report_to_json(report).encode("utf-8"), "application/json; charset=utf-8")
            elif fmt == "csv":
                self._send_bytes(report_to_csv(report).encode("utf-8"), "text/csv; charset=utf-8")
            elif fmt in {"md", "markdown"}:
                self._send_bytes(report_to_markdown(report).encode("utf-8"), "text/markdown; charset=utf-8")
            else:
                self._send_bytes(report_to_html(report).encode("utf-8"), "text/html; charset=utf-8")
            return
        self._json(snapshot)

    def _authorized(self, parsed) -> bool:
        if not API_TOKEN:
            return True
        token = self.headers.get("X-Scanner-Token", "")
        if not token:
            token = parse_qs(parsed.query).get("token", [""])[0]
        if hmac.compare_digest(token, API_TOKEN):
            return True
        self._json({"error": "token invalid"}, HTTPStatus.UNAUTHORIZED)
        return False

    def _serve_static(self, path: str) -> None:
        if path in {"", "/"}:
            file_path = WEB_ROOT / "index.html"
        elif path == "/app.js":
            file_path = WEB_ROOT / "app.js"
        elif path == "/styles.css":
            file_path = WEB_ROOT / "styles.css"
        elif path == "/favicon.svg":
            file_path = WEB_ROOT / "favicon.svg"
        else:
            self._json({"error": "not found"}, HTTPStatus.NOT_FOUND)
            return
        if not file_path.is_file():
            self._json({"error": "web assets missing"}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return
        content_type = mimetypes.guess_type(file_path.name)[0] or "application/octet-stream"
        if content_type.startswith("text/") or content_type in {"application/javascript", "application/json"}:
            content_type += "; charset=utf-8"
        self._send_bytes(file_path.read_bytes(), content_type)

    def _json(self, payload: object, status: HTTPStatus = HTTPStatus.OK) -> None:
        self._send_bytes(
            json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            "application/json; charset=utf-8",
            status,
        )

    def _send_bytes(
        self,
        payload: bytes,
        content_type: str,
        status: HTTPStatus = HTTPStatus.OK,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'self'",
        )
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt: str, *args: object) -> None:
        if str(args[1] if len(args) > 1 else "") not in {"200", "202"}:
            super().log_message(fmt, *args)


def main() -> None:
    global API_TOKEN
    parser = argparse.ArgumentParser(description="PHP2Shell Scanner Web")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--token", default="")
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        if not (WEB_ROOT / "index.html").is_file():
            raise SystemExit(f"web assets missing: {WEB_ROOT}")
        print(f"web assets: {WEB_ROOT}")
        print("self-test: OK")
        return
    loopback = args.host in {"127.0.0.1", "localhost", "::1"}
    if not loopback and not args.token:
        raise SystemExit("绑定非本机地址时必须提供 --token")
    API_TOKEN = args.token
    server = ThreadingHTTPServer((args.host, args.port), ScannerHandler)
    url = f"http://{args.host}:{args.port}/"
    if args.token:
        url += "?token=" + urllib_quote(args.token)
    print(f"PHP2Shell Scanner Web: {url}")
    print("Press Ctrl+C to stop.")
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def urllib_quote(value: str) -> str:
    from urllib.parse import quote

    return quote(value, safe="")


if __name__ == "__main__":
    main()
