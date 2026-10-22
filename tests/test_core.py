from __future__ import annotations

import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from php2shell.core import (
    ScanConfig,
    classify_php_version,
    extract_php_version,
    parse_remote_audit_output,
    parse_server_text,
    parse_target_text,
    scan_http_target,
    self_test,
)
from php2shell.report import report_to_csv, report_to_html, report_to_json


class VersionTests(unittest.TestCase):
    def test_classification(self) -> None:
        self.assertEqual(classify_php_version("8.5.11")["status"], "vulnerable")
        self.assertEqual(classify_php_version("8.5.12")["status"], "fixed")
        self.assertEqual(classify_php_version("8.4.23")["status"], "vulnerable")
        self.assertEqual(classify_php_version("8.4.27")["status"], "fixed")
        self.assertEqual(classify_php_version("8.3.35")["status"], "vulnerable")
        self.assertEqual(classify_php_version("8.3.36")["status"], "fixed")
        self.assertEqual(classify_php_version("8.2.34")["status"], "vulnerable")
        self.assertEqual(classify_php_version("8.2.35")["status"], "fixed")
        self.assertEqual(classify_php_version("7.4.33")["status"], "eol")
        self.assertEqual(classify_php_version("8.6.0")["status"], "review")

    def test_extract(self) -> None:
        self.assertEqual(extract_php_version("PHP 8.4.23 (fpm-fcgi)"), "8.4.23")
        self.assertEqual(extract_php_version("X-Powered-By: PHP/8.5.11"), "8.5.11")

    def test_self_test(self) -> None:
        self_test()


class ParserTests(unittest.TestCase):
    def test_servers_csv(self) -> None:
        servers, errors = parse_server_text(
            "name,host,port,user,key_path\n"
            "demo,192.0.2.50,22022,deploy,C:\\Users\\demo\\.ssh\\id_ed25519\n"
            "app,198.51.100.51,22022,ops,\n"
        )
        self.assertFalse(errors)
        self.assertEqual(len(servers), 2)
        self.assertEqual(servers[0].port, 22022)
        self.assertEqual(servers[1].user, "ops")

    def test_servers_shorthand(self) -> None:
        servers, errors = parse_server_text("deploy@192.0.2.60:2222\n198.51.100.61\n")
        self.assertFalse(errors)
        self.assertEqual(servers[0].user, "deploy")
        self.assertEqual(servers[0].port, 2222)
        self.assertEqual(servers[1].port, 22)

    def test_targets(self) -> None:
        targets, errors = parse_target_text("官网|https://example.com\nlocalhost:8080\n")
        self.assertFalse(errors)
        self.assertEqual(targets[0].name, "官网")
        self.assertEqual(targets[0].url, "https://example.com")
        self.assertEqual(targets[1].url, "https://localhost:8080")

    def test_invalid_target_rejected(self) -> None:
        targets, errors = parse_target_text("https://bad host.example\n")
        self.assertFalse(targets)
        self.assertEqual(len(errors), 1)

    def test_remote_output(self) -> None:
        parsed = parse_remote_audit_output(
            "META\thost=hk-1\n"
            "META\tos=Ubuntu 24.04\n"
            "BIN\t/www/server/php/84/sbin/php-fpm|fpm|PHP 8.4.23 (fpm-fcgi)\n"
            "SETTING\t/www/server/php/84/sbin/php-fpm|memory_limit => 128M => 128M\n"
            "DOCKER_PHP\tnc-app|nextcloud:stable|PHP 8.5.11 (cli)\n"
            "DOCKER_SETTING\tnc-app|session.upload_progress.enabled => On => On\n"
            "PACKAGE\tdpkg:php8.3-fpm=8.3.6-0ubuntu\n"
        )
        self.assertEqual(parsed["meta"]["host"], "hk-1")
        self.assertEqual(parsed["bins"][0]["version"], "8.4.23")
        self.assertEqual(parsed["bins"][0]["config"]["memory_limit"], "128M")
        self.assertEqual(parsed["docker_php"][0]["version"], "8.5.11")
        self.assertEqual(
            parsed["docker_php"][0]["config"]["session.upload_progress.enabled"],
            "On",
        )


class _VulnerableHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        if not self.path.startswith("/hidden"):
            self.send_header("X-Powered-By", "PHP/8.4.23")
        else:
            self.send_header("Set-Cookie", "PHPSESSID=super-secret; HttpOnly")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, fmt: str, *args: object) -> None:
        pass


class HTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _VulnerableHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def test_http_scan(self) -> None:
        from php2shell.core import TargetSpec

        result = scan_http_target(
            TargetSpec("local-test", f"http://127.0.0.1:{self.port}/"),
            ScanConfig(timeout_sec=5, verify_tls=False),
        )
        self.assertEqual(result["status"], "vulnerable")
        self.assertEqual(result["php_runtimes"][0]["version"], "8.4.23")
        self.assertIn("CVE-2026-109618", result["findings"][0]["cves"])

    def test_http_hidden_version_is_unknown_and_cookie_redacted(self) -> None:
        from php2shell.core import TargetSpec

        result = scan_http_target(
            TargetSpec("hidden", f"http://127.0.0.1:{self.port}/hidden?token=secret"),
            ScanConfig(timeout_sec=5, verify_tls=False),
        )
        self.assertEqual(result["status"], "unknown")
        self.assertTrue(result["evidence"]["set_cookie_present"])
        self.assertNotIn("super-secret", str(result))
        self.assertNotIn("token=secret", str(result))


class ReportTests(unittest.TestCase):
    def test_serializers(self) -> None:
        report = {
            "scanned_at": "2026-10-22T08:00:00+08:00",
            "scanner_version": "1.0.0",
            "summary": {"total": 1, "vulnerable": 1},
            "results": [
                {
                    "id": "ssh:test",
                    "status": "vulnerable",
                    "name": "test",
                    "mode": "ssh",
                    "address": "root@test:22",
                    "hostname": "test",
                    "os": "Linux",
                    "php_runtimes": [{"version": "8.4.23", "sapi": "fpm-fcgi", "path": "/usr/sbin/php-fpm"}],
                    "findings": [{"cves": ["CVE-2026-109618"], "reason": "test"}],
                    "fixes": [{"title": "升级", "steps": ["step"]}],
                    "evidence": {},
                    "errors": [],
                }
            ],
        }
        self.assertIn("8.4.23", report_to_json(report))
        self.assertIn("存在漏洞", report_to_csv(report))
        self.assertIn("CVE-2026-109619", report_to_html(report))


if __name__ == "__main__":
    unittest.main()
