# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional

def _connect(db_path: str) -> sqlite3.Connection:
    return sqlite3.connect(db_path, timeout=30)

def _fmt_ts(ms: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ms/1000))

def _svg_bar_chart(title: str, items: List[Tuple[str, int]], width: int = 900, height: int = 260) -> str:
    if not items:
        return f"<h3>{title}</h3><p>Нет данных.</p>"
    max_v = max(v for _, v in items) or 1
    pad = 40
    chart_w = width - pad*2
    chart_h = height - pad*2
    bar_w = max(10, chart_w // max(len(items), 1) - 6)

    svg = [f"<h3>{title}</h3>",
           f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" '
           f'xmlns="http://www.w3.org/2000/svg" role="img" aria-label="{title}">']
    # axes
    svg.append(f'<line x1="{pad}" y1="{pad}" x2="{pad}" y2="{pad+chart_h}" stroke="#333"/>')
    svg.append(f'<line x1="{pad}" y1="{pad+chart_h}" x2="{pad+chart_w}" y2="{pad+chart_h}" stroke="#333"/>')

    x = pad + 6
    for label, v in items:
        h = int(chart_h * (v / max_v))
        y = pad + chart_h - h
        svg.append(f'<rect x="{x}" y="{y}" width="{bar_w}" height="{h}" fill="#4c78a8"/>')
        # value
        svg.append(f'<text x="{x+bar_w/2}" y="{y-4}" text-anchor="middle" font-size="11" fill="#111">{v}</text>')
        # label rotated if long
        safe = (label[:18] + "…") if len(label) > 18 else label
        svg.append(f'<text x="{x+bar_w/2}" y="{pad+chart_h+14}" text-anchor="middle" font-size="10" fill="#111" '
                   f'transform="rotate(25 {x+bar_w/2} {pad+chart_h+14})">{_escape(safe)}</text>')
        x += bar_w + 6

    svg.append("</svg>")
    return "\n".join(svg)

def _escape(s: str) -> str:
    return (s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
              .replace('"',"&quot;").replace("'","&#39;"))

def generate_html_report(db_path: str, out_path: str, ts_from_ms: int, ts_to_ms: int) -> str:
    conn = _connect(db_path)
    try:
        total = conn.execute(
            "SELECT COUNT(*) FROM events WHERE ts_ms BETWEEN ? AND ?;",
            (ts_from_ms, ts_to_ms)
        ).fetchone()[0]

        by_type = conn.execute(
            "SELECT event_type, COUNT(*) c FROM events WHERE ts_ms BETWEEN ? AND ? GROUP BY event_type ORDER BY c DESC;",
            (ts_from_ms, ts_to_ms)
        ).fetchall()

        by_user = conn.execute(
            "SELECT COALESCE(user,'?') u, COUNT(*) c FROM events WHERE ts_ms BETWEEN ? AND ? GROUP BY u ORDER BY c DESC LIMIT 10;",
            (ts_from_ms, ts_to_ms)
        ).fetchall()

        by_comm = conn.execute(
            "SELECT COALESCE(comm,'?') cmm, COUNT(*) c FROM events WHERE ts_ms BETWEEN ? AND ? GROUP BY cmm ORDER BY c DESC LIMIT 10;",
            (ts_from_ms, ts_to_ms)
        ).fetchall()

        # sample latest events
        latest = conn.execute(
            "SELECT ts_ms,event_type,user,pid,comm,details_json FROM events WHERE ts_ms BETWEEN ? AND ? ORDER BY ts_ms DESC LIMIT 50;",
            (ts_from_ms, ts_to_ms)
        ).fetchall()
    finally:
        conn.close()

    html = []
    html.append("<!doctype html><meta charset='utf-8'>")
    html.append("<title>AuditMon отчет</title>")
    html.append("<style>")
    html.append("body{font-family:system-ui,Segoe UI,Arial,sans-serif; margin:24px;}")
    html.append("h1{margin:0 0 6px 0;} .muted{color:#555;}")
    html.append("table{border-collapse:collapse; width:100%; margin-top:10px;}")
    html.append("th,td{border:1px solid #ddd; padding:6px 8px; font-size:12px; vertical-align:top;}")
    html.append("th{background:#f5f5f5; text-align:left;}")
    html.append("</style>")

    html.append("<h1>AuditMon отчет</h1>")
    html.append(f"<div class='muted'>Период: {_fmt_ts(ts_from_ms)} — {_fmt_ts(ts_to_ms)}</div>")
    html.append(f"<p><b>Всего событий:</b> {int(total)}</p>")

    html.append(_svg_bar_chart("События по типам", [(str(k), int(v)) for k, v in by_type][:20]))
    html.append(_svg_bar_chart("Топ-10 пользователей", [(str(k), int(v)) for k, v in by_user]))
    html.append(_svg_bar_chart("Топ-10 процессов (comm)", [(str(k), int(v)) for k, v in by_comm]))

    html.append("<h3>Последние 50 событий</h3>")
    html.append("<table><thead><tr><th>Время</th><th>Тип</th><th>Пользователь</th><th>PID</th><th>Процесс</th><th>Детали</th></tr></thead><tbody>")
    for ts, et, user, pid, comm, details in latest:
        html.append("<tr>")
        html.append(f"<td>{_escape(_fmt_ts(int(ts)))}</td>")
        html.append(f"<td>{_escape(str(et))}</td>")
        html.append(f"<td>{_escape(str(user or ''))}</td>")
        html.append(f"<td>{_escape(str(pid or ''))}</td>")
        html.append(f"<td>{_escape(str(comm or ''))}</td>")
        # compact json
        try:
            obj = json.loads(details) if details else {}
            details_s = json.dumps(obj, ensure_ascii=False)
        except Exception:
            details_s = str(details or "")
        html.append(f"<td>{_escape(details_s[:500])}</td>")
        html.append("</tr>")
    html.append("</tbody></table>")

    out_p = Path(out_path)
    out_p.parent.mkdir(parents=True, exist_ok=True)
    out_p.write_text("\n".join(html), encoding="utf-8")
    return str(out_p)
