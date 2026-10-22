from __future__ import annotations

import json
import os
import queue
import sys
import threading
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from php2shell.core import ScanConfig, parse_server_text, parse_target_text, scan_job, self_test
from php2shell.report import (
    report_to_csv,
    report_to_html,
    report_to_json,
    report_to_markdown,
    status_label,
)


APP_TITLE = "PHP2Shell 安全扫描器 · PC 版"


class ScannerApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1260x850")
        self.minsize(1000, 700)
        self.configure(bg="#07111f")
        self.queue: queue.Queue[tuple[str, object]] = queue.Queue()
        self.report: dict | None = None
        self.result_by_iid: dict[str, dict] = {}
        self.scanning = False
        self._configure_style()
        self._build_ui()
        self.after(120, self._poll_queue)

    def _configure_style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", font=("Microsoft YaHei UI", 10))
        style.configure("TFrame", background="#07111f")
        style.configure("Panel.TFrame", background="#0d1b2e")
        style.configure("TLabel", background="#07111f", foreground="#e8f0fa")
        style.configure("Muted.TLabel", background="#07111f", foreground="#8fa5bf")
        style.configure("Title.TLabel", font=("Microsoft YaHei UI", 22, "bold"), foreground="#f4f8fc")
        style.configure("Subtitle.TLabel", foreground="#8fa5bf")
        style.configure("TButton", padding=(12, 8), background="#173451", foreground="#eaf4ff")
        style.map("TButton", background=[("active", "#214a70")])
        style.configure("Accent.TButton", background="#2563eb", foreground="white", font=("Microsoft YaHei UI", 10, "bold"))
        style.map("Accent.TButton", background=[("active", "#3478f6")])
        style.configure("Treeview", rowheight=28, background="#0d1b2e", fieldbackground="#0d1b2e", foreground="#e8f0fa")
        style.configure("Treeview.Heading", background="#12263d", foreground="#bcd0e7")
        style.map("Treeview", background=[("selected", "#1e4f7a")])
        style.configure("TNotebook", background="#07111f", borderwidth=0)
        style.configure("TNotebook.Tab", padding=(16, 8), background="#12263d", foreground="#c4d7eb")
        style.map("TNotebook.Tab", background=[("selected", "#183553")])

    def _build_ui(self) -> None:
        container = ttk.Frame(self, padding=18)
        container.pack(fill="both", expand=True)

        header = ttk.Frame(container)
        header.pack(fill="x")
        ttk.Label(header, text="PHP2Shell 安全扫描器", style="Title.TLabel").pack(side="left")
        ttk.Label(
            header,
            text="只读盘点 · CVE-2026-109618 / CVE-2026-109619",
            style="Subtitle.TLabel",
        ).pack(side="left", padx=(18, 0), pady=(8, 0))

        io_frame = ttk.Frame(container, style="Panel.TFrame", padding=14)
        io_frame.pack(fill="x", pady=(14, 10))
        notebook = ttk.Notebook(io_frame)
        notebook.pack(fill="x")

        server_tab = ttk.Frame(notebook, style="Panel.TFrame", padding=10)
        target_tab = ttk.Frame(notebook, style="Panel.TFrame", padding=10)
        notebook.add(server_tab, text="SSH 服务器")
        notebook.add(target_tab, text="HTTP 目标")

        ttk.Label(
            server_tab,
            text="每行：name,host,port,user,key_path；也可只写 host / user@host:port。私钥可为空，走 ssh-agent 或默认密钥。",
            style="Muted.TLabel",
        ).pack(anchor="w")
        self.server_text = tk.Text(
            server_tab,
            height=7,
            relief="flat",
            bg="#07111f",
            fg="#e8f0fa",
            insertbackground="white",
            padx=10,
            pady=8,
            font=("Consolas", 10),
        )
        self.server_text.pack(fill="x", pady=(6, 0))
        self.server_text.insert(
            "1.0",
            "name,host,port,user,key_path\n"
            "# web-prod,192.0.2.10,2222,deploy,C:\\Users\\demo\\.ssh\\id_ed25519\n",
        )

        ttk.Label(
            target_tab,
            text="每行一个 URL；也可写“名称|https://example.com”。只读取响应头和有限页面内容，不发送漏洞利用请求。",
            style="Muted.TLabel",
        ).pack(anchor="w")
        self.target_text = tk.Text(
            target_tab,
            height=7,
            relief="flat",
            bg="#07111f",
            fg="#e8f0fa",
            insertbackground="white",
            padx=10,
            pady=8,
            font=("Consolas", 10),
        )
        self.target_text.pack(fill="x", pady=(6, 0))

        options = ttk.Frame(container, style="Panel.TFrame", padding=12)
        options.pack(fill="x", pady=(0, 10))
        ttk.Label(options, text="默认私钥", background="#0d1b2e").pack(side="left")
        self.key_var = tk.StringVar(value=str(Path.home() / ".ssh" / "id_ed25519"))
        ttk.Entry(options, textvariable=self.key_var, width=48).pack(side="left", padx=8)
        ttk.Button(options, text="选择", command=self._pick_key).pack(side="left")
        ttk.Label(options, text="并发", background="#0d1b2e").pack(side="left", padx=(18, 4))
        self.workers_var = tk.StringVar(value="8")
        ttk.Spinbox(options, from_=1, to=64, width=5, textvariable=self.workers_var).pack(side="left")
        ttk.Label(options, text="超时秒", background="#0d1b2e").pack(side="left", padx=(14, 4))
        self.timeout_var = tk.StringVar(value="25")
        ttk.Spinbox(options, from_=5, to=180, width=5, textvariable=self.timeout_var).pack(side="left")
        self.verify_tls_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options, text="校验 TLS", variable=self.verify_tls_var).pack(side="left", padx=14)

        actions = ttk.Frame(container)
        actions.pack(fill="x", pady=(0, 10))
        self.scan_button = ttk.Button(actions, text="开始扫描", style="Accent.TButton", command=self._start_scan)
        self.scan_button.pack(side="left")
        ttk.Button(actions, text="导入服务器 CSV", command=self._load_csv).pack(side="left", padx=8)
        ttk.Button(actions, text="导出 HTML", command=lambda: self._export("html")).pack(side="left")
        ttk.Button(actions, text="导出 CSV", command=lambda: self._export("csv")).pack(side="left", padx=8)
        ttk.Button(actions, text="导出 JSON", command=lambda: self._export("json")).pack(side="left")
        ttk.Button(actions, text="清空", command=self._clear).pack(side="right")
        self.progress = ttk.Progressbar(actions, mode="determinate", length=240)
        self.progress.pack(side="right", padx=12)
        self.progress_label = ttk.Label(actions, text="等待扫描", style="Muted.TLabel")
        self.progress_label.pack(side="right")

        paned = ttk.Panedwindow(container, orient="vertical")
        paned.pack(fill="both", expand=True)
        table_frame = ttk.Frame(paned)
        detail_frame = ttk.Frame(paned)
        paned.add(table_frame, weight=3)
        paned.add(detail_frame, weight=2)

        columns = ("status", "name", "mode", "address", "php", "finding")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")
        self.tree.heading("status", text="状态")
        self.tree.heading("name", text="名称")
        self.tree.heading("mode", text="模式")
        self.tree.heading("address", text="地址")
        self.tree.heading("php", text="PHP 运行时")
        self.tree.heading("finding", text="CVE / 说明")
        self.tree.column("status", width=100, stretch=False)
        self.tree.column("name", width=160)
        self.tree.column("mode", width=70, stretch=False)
        self.tree.column("address", width=240)
        self.tree.column("php", width=230)
        self.tree.column("finding", width=480)
        yscroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        xscroll = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)
        self.tree.bind("<<TreeviewSelect>>", self._show_detail)

        self.detail = tk.Text(
            detail_frame,
            relief="flat",
            bg="#0d1b2e",
            fg="#dbe8f6",
            padx=14,
            pady=12,
            wrap="word",
            font=("Microsoft YaHei UI", 10),
        )
        detail_scroll = ttk.Scrollbar(detail_frame, orient="vertical", command=self.detail.yview)
        self.detail.configure(yscrollcommand=detail_scroll.set)
        self.detail.pack(side="left", fill="both", expand=True)
        detail_scroll.pack(side="right", fill="y")
        self.detail.insert("1.0", "扫描结果会显示在这里。双击或选中任意结果可查看证据和修复路径。")

    def _pick_key(self) -> None:
        value = filedialog.askopenfilename(title="选择 SSH 私钥")
        if value:
            self.key_var.set(value)

    def _load_csv(self) -> None:
        value = filedialog.askopenfilename(title="导入服务器 CSV", filetypes=[("CSV", "*.csv"), ("All", "*.*")])
        if not value:
            return
        try:
            text = Path(value).read_text(encoding="utf-8-sig")
            self.server_text.delete("1.0", "end")
            self.server_text.insert("1.0", text)
        except Exception as exc:
            messagebox.showerror(APP_TITLE, f"读取 CSV 失败：{exc}")

    def _clear(self) -> None:
        if self.scanning:
            return
        self.report = None
        self.result_by_iid.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.detail.delete("1.0", "end")
        self.progress["value"] = 0
        self.progress_label.configure(text="等待扫描")

    def _start_scan(self) -> None:
        if self.scanning:
            return
        servers, server_errors = parse_server_text(self.server_text.get("1.0", "end"))
        targets, target_errors = parse_target_text(self.target_text.get("1.0", "end"))
        errors = server_errors + target_errors
        if errors:
            messagebox.showerror(APP_TITLE, "\n".join(errors[:20]))
            return
        if not servers and not targets:
            messagebox.showinfo(APP_TITLE, "请至少填写一台 SSH 服务器或一个 HTTP 目标。")
            return
        try:
            config = ScanConfig(
                timeout_sec=int(self.timeout_var.get()),
                workers=int(self.workers_var.get()),
                default_key_path=self.key_var.get().strip(),
                verify_tls=self.verify_tls_var.get(),
            )
        except ValueError:
            messagebox.showerror(APP_TITLE, "并发数和超时必须是整数。")
            return
        self.scanning = True
        self.scan_button.configure(state="disabled")
        self.progress.configure(maximum=len(servers) + len(targets), value=0)
        self.progress_label.configure(text=f"0 / {len(servers) + len(targets)}")
        self.report = None
        self.result_by_iid.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)

        def worker() -> None:
            try:
                report = scan_job(
                    servers,
                    targets,
                    config,
                    on_result=lambda result: self.queue.put(("result", result)),
                    on_progress=lambda done, total: self.queue.put(("progress", (done, total))),
                )
                self.queue.put(("done", report))
            except Exception as exc:
                self.queue.put(("fatal", str(exc)))

        threading.Thread(target=worker, daemon=True).start()

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == "result":
                    self._add_result(payload)
                elif kind == "progress":
                    done, total = payload
                    self.progress["value"] = done
                    self.progress_label.configure(text=f"{done} / {total}")
                elif kind == "done":
                    self.report = payload
                    self.scanning = False
                    self.scan_button.configure(state="normal")
                    summary = payload.get("summary", {})
                    self.progress_label.configure(
                        text=f"完成：漏洞 {summary.get('vulnerable', 0)} / 已修复 {summary.get('fixed', 0)}"
                    )
                elif kind == "fatal":
                    self.scanning = False
                    self.scan_button.configure(state="normal")
                    self.progress_label.configure(text="扫描失败")
                    messagebox.showerror(APP_TITLE, str(payload))
        except queue.Empty:
            pass
        self.after(120, self._poll_queue)

    def _add_result(self, result: dict) -> None:
        runtimes = ", ".join(
            f"{x.get('version') or '?'} {x.get('sapi', '')}".strip()
            for x in result.get("php_runtimes", [])
        ) or "—"
        finding = "; ".join(
            f"{', '.join(x.get('cves', []))}: {x.get('reason', '')}" for x in result.get("findings", [])
        )
        if not finding and result.get("errors"):
            finding = "; ".join(result["errors"])
        if not finding:
            finding = "未命中"
        iid = self.tree.insert(
            "",
            "end",
            values=(
                status_label(result.get("status", "unknown")),
                result.get("name", ""),
                result.get("mode", ""),
                result.get("address", ""),
                runtimes,
                finding,
            ),
        )
        self.result_by_iid[iid] = result

    def _show_detail(self, _event: object = None) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        result = self.result_by_iid.get(selected[0])
        if not result:
            return
        single = {
            "scanner": "PHP2Shell Scanner",
            "scanner_version": "1.0.2",
            "scanned_at": result.get("scanned_at", ""),
            "summary": {"total": 1, result.get("status", "unknown"): 1},
            "results": [result],
        }
        text = report_to_markdown(single)
        for fix in result.get("fixes", []):
            text += f"\n## {fix.get('title', '修复建议')}\n"
            for index, step in enumerate(fix.get("steps", []), 1):
                text += f"{index}. {step}\n"
        if result.get("evidence"):
            text += "\n## 原始证据\n```json\n" + json.dumps(result["evidence"], ensure_ascii=False, indent=2) + "\n```\n"
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", text)

    def _export(self, fmt: str) -> None:
        if not self.report:
            messagebox.showinfo(APP_TITLE, "还没有完成的扫描报告。")
            return
        extension = {"html": ".html", "csv": ".csv", "json": ".json"}[fmt]
        path = filedialog.asksaveasfilename(
            title="导出扫描报告",
            defaultextension=extension,
            filetypes=[(fmt.upper(), f"*{extension}"), ("All", "*.*")],
            initialfile=f"php2shell-report-{datetime_stamp()}{extension}",
        )
        if not path:
            return
        content = {"html": report_to_html, "csv": report_to_csv, "json": report_to_json}[fmt](self.report)
        Path(path).write_text(content, encoding="utf-8")
        messagebox.showinfo(APP_TITLE, f"报告已保存：\n{path}")


def datetime_stamp() -> str:
    from datetime import datetime

    return datetime.now().strftime("%Y%m%d-%H%M%S")


def main() -> None:
    if "--self-test" in sys.argv:
        self_test()
        print("self-test: OK")
        return
    app = ScannerApp()
    app.mainloop()


if __name__ == "__main__":
    main()
