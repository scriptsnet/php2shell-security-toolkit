from __future__ import annotations

import argparse
import sys
from pathlib import Path

from php2shell.core import ScanConfig, parse_server_text, parse_target_text, scan_job, self_test
from php2shell.report import report_to_csv, report_to_html, report_to_json, report_to_markdown


def main() -> None:
    parser = argparse.ArgumentParser(description="PHP2Shell Scanner CLI")
    parser.add_argument("--servers-file", default="", help="服务器 CSV 文件")
    parser.add_argument("--targets-file", default="", help="HTTP 目标文本文件")
    parser.add_argument("--server", action="append", default=[], help="单个服务器，可重复")
    parser.add_argument("--target", action="append", default=[], help="单个 URL，可重复")
    parser.add_argument("--key", default="", help="默认 SSH 私钥")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--timeout", type=int, default=25)
    parser.add_argument("--insecure", action="store_true", help="不校验 HTTPS 证书")
    parser.add_argument("--format", choices=["json", "csv", "html", "md"], default="json")
    parser.add_argument("--output", default="", help="输出文件；省略时打印到标准输出")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        print("self-test: OK")
        return
    server_text = "\n".join(args.server)
    if args.servers_file:
        server_text += "\n" + Path(args.servers_file).read_text(encoding="utf-8-sig")
    target_text = "\n".join(args.target)
    if args.targets_file:
        target_text += "\n" + Path(args.targets_file).read_text(encoding="utf-8-sig")
    servers, server_errors = parse_server_text(server_text)
    targets, target_errors = parse_target_text(target_text)
    errors = server_errors + target_errors
    if errors:
        raise SystemExit("\n".join(errors))
    report = scan_job(
        servers,
        targets,
        ScanConfig(
            timeout_sec=args.timeout,
            workers=args.workers,
            default_key_path=args.key,
            verify_tls=not args.insecure,
        ),
        on_progress=lambda done, total: print(f"\r进度 {done}/{total}", end="", file=sys.stderr, flush=True),
    )
    print("", file=sys.stderr)
    serializer = {
        "json": report_to_json,
        "csv": report_to_csv,
        "html": report_to_html,
        "md": report_to_markdown,
    }[args.format]
    content = serializer(report)
    if args.output:
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        summary = report["summary"]
        print(
            f"报告已保存: {path} | 漏洞={summary.get('vulnerable', 0)} "
            f"高风险={summary.get('at_risk', 0)} 已修复={summary.get('fixed', 0)}",
            file=sys.stderr,
        )
    else:
        print(content)


if __name__ == "__main__":
    main()
