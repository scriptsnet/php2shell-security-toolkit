from __future__ import annotations

import csv
import html
import io
import json
from pathlib import Path
from typing import Any

STATUS_LABELS = {
    "vulnerable": "存在漏洞",
    "at_risk": "高风险 / EOL",
    "unknown": "无法确认",
    "fixed": "已修复",
    "no_php": "未检测到 PHP",
    "error": "扫描失败",
}


def status_label(status: str) -> str:
    return STATUS_LABELS.get(status, status)


def report_to_json(report: dict[str, Any]) -> str:
    return json.dumps(report, ensure_ascii=False, indent=2)


def report_to_csv(report: dict[str, Any]) -> str:
    out = io.StringIO(newline="")
    writer = csv.writer(out)
    writer.writerow(
        [
            "状态",
            "名称",
            "模式",
            "地址",
            "主机名",
            "系统",
            "PHP 运行时",
            "命中 CVE",
            "修复建议",
            "错误",
        ]
    )
    for result in report.get("results", []):
        runtimes = []
        for runtime in result.get("php_runtimes", []):
            runtimes.append(
                f"{runtime.get('version') or 'unknown'} {runtime.get('sapi', '')} {runtime.get('path', '')}".strip()
            )
        cves = sorted({cve for finding in result.get("findings", []) for cve in finding.get("cves", [])})
        fixes = [x.get("title", "") for x in result.get("fixes", [])]
        writer.writerow(
            [
                status_label(result.get("status", "unknown")),
                result.get("name", ""),
                result.get("mode", ""),
                result.get("address", ""),
                result.get("hostname", ""),
                result.get("os", ""),
                "; ".join(runtimes),
                ", ".join(cves),
                "; ".join(fixes),
                "; ".join(result.get("errors", [])),
            ]
        )
    return "\ufeff" + out.getvalue()


def report_to_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    lines = [
        "# PHP2Shell 安全扫描报告",
        "",
        f"- 扫描时间：{report.get('scanned_at', '')}",
        f"- 目标数：{summary.get('total', 0)}",
        f"- 存在漏洞：{summary.get('vulnerable', 0)}",
        f"- 高风险 / EOL：{summary.get('at_risk', 0)}",
        f"- 已修复：{summary.get('fixed', 0)}",
        f"- 无法确认：{summary.get('unknown', 0)}",
        f"- 扫描失败：{summary.get('error', 0)}",
        "",
        "| 状态 | 名称 | 地址 | PHP | CVE / 说明 |",
        "| --- | --- | --- | --- | --- |",
    ]
    for result in report.get("results", []):
        versions = ", ".join(
            f"{x.get('version') or 'unknown'} ({x.get('sapi', '')})"
            for x in result.get("php_runtimes", [])
        ) or "—"
        notes = "; ".join(
            f"{', '.join(x.get('cves', []))}: {x.get('reason', '')}" for x in result.get("findings", [])
        )
        if not notes and result.get("errors"):
            notes = "; ".join(result["errors"])
        lines.append(
            "| {status} | {name} | {address} | {versions} | {notes} |".format(
                status=status_label(result.get("status", "unknown")),
                name=_md(result.get("name", "")),
                address=_md(result.get("address", "")),
                versions=_md(versions),
                notes=_md(notes or "—"),
            )
        )
    return "\n".join(lines) + "\n"


def _md(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", "<br>")


def report_to_html(report: dict[str, Any]) -> str:
    summary = report.get("summary", {})
    cards = [
        ("目标", summary.get("total", 0)),
        ("存在漏洞", summary.get("vulnerable", 0)),
        ("高风险 / EOL", summary.get("at_risk", 0)),
        ("已修复", summary.get("fixed", 0)),
        ("无法确认", summary.get("unknown", 0)),
        ("失败", summary.get("error", 0)),
    ]
    card_html = "".join(
        f'<div class="stat"><span>{html.escape(str(label))}</span><strong>{value}</strong></div>'
        for label, value in cards
    )
    rows = []
    details = []
    for result in report.get("results", []):
        status = result.get("status", "unknown")
        runtimes = "<br>".join(
            html.escape(
                f"{x.get('version') or 'unknown'} · {x.get('sapi', '')} · {x.get('path', '')}"
            )
            for x in result.get("php_runtimes", [])
        ) or "—"
        findings = "<br>".join(
            html.escape(f"{', '.join(x.get('cves', []))} · {x.get('reason', '')}")
            for x in result.get("findings", [])
        ) or "—"
        rows.append(
            f"""
            <tr>
              <td><span class="pill {html.escape(status)}">{html.escape(status_label(status))}</span></td>
              <td><strong>{html.escape(result.get('name', ''))}</strong><small>{html.escape(result.get('address', ''))}</small></td>
              <td>{html.escape(result.get('hostname', ''))}<small>{html.escape(result.get('os', ''))}</small></td>
              <td>{runtimes}</td>
              <td>{findings}</td>
            </tr>
            """
        )
        fix_blocks = []
        for fix in result.get("fixes", []):
            steps = "".join(f"<li>{html.escape(str(step))}</li>" for step in fix.get("steps", []))
            fix_blocks.append(f"<h4>{html.escape(fix.get('title', '修复建议'))}</h4><ol>{steps}</ol>")
        errors = ""
        if result.get("errors"):
            errors = "<h4>扫描信息</h4><pre>" + html.escape("\n".join(result["errors"])) + "</pre>"
        evidence = result.get("evidence", {})
        evidence_json = html.escape(json.dumps(evidence, ensure_ascii=False, indent=2)) if evidence else "{}"
        details.append(
            f"""
            <details>
              <summary>{html.escape(result.get('name', ''))} · {html.escape(status_label(status))}</summary>
              <div class="detail-grid">
                <div>
                  <h4>修复路径</h4>
                  {''.join(fix_blocks) or '<p>未发现需要修复的运行栈。</p>'}
                  {errors}
                </div>
                <div>
                  <h4>证据</h4>
                  <pre>{evidence_json[:12000]}</pre>
                </div>
              </div>
            </details>
            """
        )
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PHP2Shell 安全扫描报告</title>
<style>
:root{{color-scheme:dark;--bg:#07111f;--panel:#0d1b2e;--line:#243a54;--text:#e8f0fa;--muted:#8fa5bf;--red:#ff5d73;--amber:#ffbf47;--green:#42d392;--blue:#55a8ff}}
*{{box-sizing:border-box}}body{{margin:0;background:radial-gradient(circle at top right,#15385b 0,var(--bg) 38%);color:var(--text);font:14px/1.55 "Segoe UI","Microsoft YaHei",sans-serif}}
main{{max-width:1500px;margin:auto;padding:32px}}h1{{font-size:30px;margin:0 0 6px}}p.meta,small{{color:var(--muted);display:block}}.stats{{display:grid;grid-template-columns:repeat(6,minmax(120px,1fr));gap:12px;margin:24px 0}}
.stat{{background:rgba(13,27,46,.86);border:1px solid var(--line);border-radius:14px;padding:15px}}.stat span{{color:var(--muted)}}.stat strong{{font-size:28px;display:block}}
.table-wrap{{overflow:auto;border:1px solid var(--line);border-radius:14px;background:var(--panel)}}table{{width:100%;border-collapse:collapse;min-width:900px}}th,td{{text-align:left;padding:12px;border-bottom:1px solid var(--line);vertical-align:top}}th{{color:var(--muted);font-weight:600}}
.pill{{display:inline-block;padding:4px 9px;border-radius:999px;font-weight:700;font-size:12px}}.pill.vulnerable{{background:#551825;color:#ff9baa}}.pill.at_risk{{background:#4a3513;color:#ffd379}}.pill.fixed{{background:#103d2e;color:#7af0bc}}.pill.unknown,.pill.no_php{{background:#183553;color:#9dceff}}.pill.error{{background:#3a2732;color:#ffb3c2}}
details{{margin-top:14px;background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:14px}}summary{{cursor:pointer;font-weight:700}}.detail-grid{{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-top:16px}}pre{{white-space:pre-wrap;word-break:break-word;background:#07111f;padding:12px;border-radius:10px;max-height:620px;overflow:auto}}h4{{margin:16px 0 6px;color:#9dceff}}
@media(max-width:900px){{main{{padding:18px}}.stats{{grid-template-columns:repeat(2,1fr)}}.detail-grid{{grid-template-columns:1fr}}}}
</style>
</head>
<body><main>
<h1>PHP2Shell 安全扫描报告</h1>
<p class="meta">扫描时间：{html.escape(report.get('scanned_at', ''))} · 漏洞：CVE-2026-109618 / CVE-2026-109619 · 扫描器 v{html.escape(report.get('scanner_version', ''))}</p>
<div class="stats">{card_html}</div>
<div class="table-wrap"><table>
<thead><tr><th>状态</th><th>服务器 / 目标</th><th>系统</th><th>PHP 运行时</th><th>判定依据</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></div>
<h2>逐项修复建议</h2>
{''.join(details)}
</main></body></html>"""


def write_report(path: str | Path, report: dict[str, Any], fmt: str) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fmt = fmt.lower()
    if fmt == "json":
        content = report_to_json(report)
    elif fmt == "csv":
        content = report_to_csv(report)
    elif fmt == "html":
        content = report_to_html(report)
    elif fmt in {"md", "markdown"}:
        content = report_to_markdown(report)
    else:
        raise ValueError(f"不支持的报告格式: {fmt}")
    target.write_text(content, encoding="utf-8")
    return target
