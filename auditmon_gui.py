# -*- coding: utf-8 -*-
from __future__ import annotations

import json
import os
import re
import time
import sqlite3
import webbrowser
from pathlib import Path
from typing import Any, Dict, Optional, List, Tuple, Union

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog

from auditmon_common import load_config, save_config, verify_gui_password, set_gui_password
from report import generate_html_report


# -------------------- helpers --------------------

def _fmt_ts(ms: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ms / 1000))


def _parse_date(date_s: str) -> Tuple[Optional[time.struct_time], Optional[str]]:
    s = (date_s or "").strip()
    if not s:
        return None, None
    try:
        return time.strptime(s, "%Y-%m-%d"), None
    except Exception:
        return None, "bad"


def _parse_time(time_s: str) -> Tuple[Optional[Tuple[int, int, int]], Optional[str]]:
    s = (time_s or "").strip()
    if not s:
        return None, None
    m = re.fullmatch(r"(\d{1,2}):(\d{2})(?::(\d{2}))?", s)
    if not m:
        return None, "bad"
    hh = int(m.group(1))
    mm = int(m.group(2))
    ss = int(m.group(3) or "0")
    if not (0 <= hh <= 23 and 0 <= mm <= 59 and 0 <= ss <= 59):
        return None, "bad"
    return (hh, mm, ss), None


def _to_ms(date_s: str, time_s: str, default_time: Tuple[int, int, int]) -> Tuple[Optional[int], Optional[str]]:
    """
    If date is empty -> None (no time boundary). Time is ignored in that case.
    If date exists but time empty -> default_time.
    """
    d, derr = _parse_date(date_s)
    if derr:
        return None, "bad"
    if d is None:
        return None, None

    t, terr = _parse_time(time_s)
    if terr:
        return None, "bad"
    if t is None:
        t = default_time

    dt = (d.tm_year, d.tm_mon, d.tm_mday, t[0], t[1], t[2], 0, 0, -1)
    try:
        return int(time.mktime(dt) * 1000), None
    except Exception:
        return None, "bad"


def _json_pretty(s: str) -> str:
    try:
        return json.dumps(json.loads(s or "{}"), ensure_ascii=False, indent=2)
    except Exception:
        return s or ""


def _safe_bool(v: Any) -> bool:
    return bool(v) is True


# -------------------- strict query parsing --------------------
# Only: key:"value" with operators AND/OR/NOT (uppercase) and parentheses.
# Values must be in double quotes always (including "null").

_ALLOWED_KEYS = {"user", "type", "event_type", "pid", "ppid", "uid", "comm", "details", "id"}
_LIKE_KEYS = {"comm", "details"}

_TERM_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\s*:\s*"((?:\\.|[^"\\])*)"')


def _unescape_quoted(v: str) -> str:
    out = []
    i = 0
    while i < len(v):
        if v[i] == "\\" and i + 1 < len(v):
            out.append(v[i + 1])
            i += 2
        else:
            out.append(v[i])
            i += 1
    return "".join(out)


Token = Tuple[str, Any]  # ("TERM",(k,v)) | ("OP","AND"/"OR"/"NOT") | ("LP","(") | ("RP",")")


def _lex_strict(q: str) -> Tuple[Optional[List[Token]], Optional[str], Optional[str]]:
    """
    Returns (tokens, err_kind, err_detail)
    err_kind: "unknown_key" | "bad"
    err_detail: key name if unknown
    """
    s = (q or "").strip()
    if not s:
        return [], None, None

    i = 0
    n = len(s)
    tokens: List[Token] = []

    def _skip_ws(j: int) -> int:
        while j < n and s[j].isspace():
            j += 1
        return j

    def _is_boundary(idx: int, length: int) -> bool:
        end = idx + length
        return end == n or s[end].isspace() or s[end] in "()"

    while True:
        i = _skip_ws(i)
        if i >= n:
            break

        ch = s[i]
        if ch == "(":
            tokens.append(("LP", "("))
            i += 1
            continue
        if ch == ")":
            tokens.append(("RP", ")"))
            i += 1
            continue

        if s.startswith("AND", i) and _is_boundary(i, 3):
            tokens.append(("OP", "AND"))
            i += 3
            continue
        if s.startswith("OR", i) and _is_boundary(i, 2):
            tokens.append(("OP", "OR"))
            i += 2
            continue
        if s.startswith("NOT", i) and _is_boundary(i, 3):
            tokens.append(("OP", "NOT"))
            i += 3
            continue

        m = _TERM_RE.match(s, i)
        if not m:
            return None, "bad", None

        key = m.group(1)
        raw_val = m.group(2)
        i = m.end()

        key_norm = key.lower()
        if key_norm not in _ALLOWED_KEYS:
            return None, "unknown_key", key
        val = _unescape_quoted(raw_val)
        tokens.append(("TERM", (key_norm, val)))

    return tokens, None, None


class _Term:
    __slots__ = ("k", "v")
    def __init__(self, k: str, v: str):
        self.k = k
        self.v = v

class _Not:
    __slots__ = ("x",)
    def __init__(self, x: "AST"):
        self.x = x

class _Bin:
    __slots__ = ("op", "a", "b")
    def __init__(self, op: str, a: "AST", b: "AST"):
        self.op = op  # "AND" or "OR"
        self.a = a
        self.b = b

AST = Union[_Term, _Not, _Bin]


class _Parser:
    def __init__(self, tokens: List[Token]):
        self.toks = tokens
        self.i = 0

    def _peek(self) -> Optional[Token]:
        if self.i >= len(self.toks):
            return None
        return self.toks[self.i]

    def _eat(self, ttype: str, val: Optional[str] = None) -> bool:
        p = self._peek()
        if not p:
            return False
        if p[0] != ttype:
            return False
        if val is not None and p[1] != val:
            return False
        self.i += 1
        return True

    def parse(self) -> Optional[AST]:
        if not self.toks:
            return None
        x = self._parse_or()
        if x is None:
            return None
        if self.i != len(self.toks):
            return None
        return x

    # or_expr := and_expr (OR and_expr)*
    def _parse_or(self) -> Optional[AST]:
        x = self._parse_and()
        if x is None:
            return None
        while self._eat("OP", "OR"):
            y = self._parse_and()
            if y is None:
                return None
            x = _Bin("OR", x, y)
        return x

    # and_expr := unary (AND unary)*
    def _parse_and(self) -> Optional[AST]:
        x = self._parse_unary()
        if x is None:
            return None
        while self._eat("OP", "AND"):
            y = self._parse_unary()
            if y is None:
                return None
            x = _Bin("AND", x, y)
        return x

    # unary := NOT unary | primary
    def _parse_unary(self) -> Optional[AST]:
        if self._eat("OP", "NOT"):
            x = self._parse_unary()
            if x is None:
                return None
            return _Not(x)
        return self._parse_primary()

    def _parse_primary(self) -> Optional[AST]:
        p = self._peek()
        if not p:
            return None
        if p[0] == "TERM":
            self.i += 1
            k, v = p[1]
            return _Term(k, v)
        if self._eat("LP", "("):
            x = self._parse_or()
            if x is None:
                return None
            if not self._eat("RP", ")"):
                return None
            return x
        return None


def _compile_ast(node: AST) -> Tuple[str, List[Any], Optional[str]]:
    def is_null(v: str) -> bool:
        return v.strip().lower() == "null"

    def term_sql(k: str, v: str) -> Tuple[str, List[Any], Optional[str]]:
        if k == "type":
            k = "event_type"

        if k in _LIKE_KEYS:
            col = "comm" if k == "comm" else "details_json"
            if is_null(v):
                return f"{col} IS NULL", [], None
            return f"{col} LIKE ?", [f"%{v}%"], None

        col = "event_type" if k == "event_type" else k
        if is_null(v):
            return f"{col} IS NULL", [], None

        if col in ("pid", "ppid", "uid", "id"):
            if not re.fullmatch(r"\d+", v.strip()):
                return "", [], "bad"
            return f"{col} = ?", [int(v)], None

        return f"{col} = ?", [v], None

    if isinstance(node, _Term):
        s, a, ek = term_sql(node.k, node.v)
        return s, a, ek

    if isinstance(node, _Not):
        s, a, ek = _compile_ast(node.x)
        if ek:
            return "", [], ek
        return f"NOT ({s})", a, None

    if isinstance(node, _Bin):
        sa, aa, eka = _compile_ast(node.a)
        if eka:
            return "", [], eka
        sb, ab, ekb = _compile_ast(node.b)
        if ekb:
            return "", [], ekb
        op = "AND" if node.op == "AND" else "OR"
        return f"({sa} {op} {sb})", aa + ab, None

    return "", [], "bad"


def _where_from_query(q: str) -> Tuple[Optional[str], List[Any], Optional[str], Optional[str]]:
    tokens, ek, ed = _lex_strict(q)
    if ek:
        return None, [], ek, ed
    if not tokens:
        return None, [], None, None

    ast = _Parser(tokens).parse()
    if ast is None:
        return None, [], "bad", None

    sql, args, ek2 = _compile_ast(ast)
    if ek2:
        return None, [], "bad", None

    return sql, args, None, None


# -------------------- rule editor dialog --------------------

class RuleDialog(tk.Toplevel):
    _DEFAULT_MESSAGE = "{event_type} user={user} pid={pid} comm={comm}"

    def __init__(self, parent: tk.Tk, rule: Optional[Dict[str, Any]] = None):
        super().__init__(parent)
        self.title("Правило оповещения")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self._result: Optional[Dict[str, Any]] = None
        r = rule or {}

        self.var_enabled = tk.BooleanVar(value=bool(r.get("enabled", True)))

        name = r.get("name", "")
        when = r.get("when") or {}
        types = when.get("event_type") or []
        users = when.get("user") or []
        comm_contains = when.get("comm_contains", "")

        frm = ttk.Frame(self, padding=12)
        frm.grid(row=0, column=0, sticky="nsew")

        def L(text: str, row: int):
            ttk.Label(frm, text=text).grid(row=row, column=0, sticky="w", pady=4)

        self.e_name = ttk.Entry(frm, width=50)
        self.e_name.insert(0, str(name))

        self.e_types = ttk.Entry(frm, width=50)
        self.e_types.insert(0, ", ".join([str(x) for x in types]))

        self.e_users = ttk.Entry(frm, width=50)
        # отображаем None как "null"; если в старом конфиге почему-то лежит строка "null" — тоже показываем как null
        users_str = ", ".join(["null" if (u is None or str(u).strip().lower() == "null") else str(u) for u in users])
        self.e_users.insert(0, users_str)

        self.e_comm = ttk.Entry(frm, width=50)
        self.e_comm.insert(0, str(comm_contains or ""))

        L("Имя правила", 0)
        self.e_name.grid(row=0, column=1, sticky="w")

        ttk.Checkbutton(frm, text="Включено", variable=self.var_enabled).grid(row=1, column=1, sticky="w", pady=4)

        L("Типы событий (через запятую)", 2)
        self.e_types.grid(row=2, column=1, sticky="w")

        L("Пользователи (через запятую, можно null)", 3)
        self.e_users.grid(row=3, column=1, sticky="w")

        L("comm содержит (подстрока)", 4)
        self.e_comm.grid(row=4, column=1, sticky="w")

        btns = ttk.Frame(frm)
        btns.grid(row=5, column=0, columnspan=2, sticky="e", pady=(10, 0))
        ttk.Button(btns, text="Отмена", command=self._cancel).pack(side="right", padx=(8, 0))
        ttk.Button(btns, text="OK", command=self._ok).pack(side="right")

        self.bind("<Return>", lambda _e: self._ok())
        self.bind("<Escape>", lambda _e: self._cancel())

        self._center(parent)

    def _center(self, parent: tk.Tk):
        self.update_idletasks()
        px = parent.winfo_rootx()
        py = parent.winfo_rooty()
        pw = parent.winfo_width()
        ph = parent.winfo_height()
        w = self.winfo_width()
        h = self.winfo_height()
        x = px + max(0, (pw - w) // 2)
        y = py + max(0, (ph - h) // 2)
        self.geometry(f"+{x}+{y}")

    def _cancel(self):
        self._result = None
        self.destroy()

    @staticmethod
    def _normalize_user_token(tok: str) -> Optional[str]:
        u = (tok or "").strip()
        if not u:
            return ""  # сигнал "пропустить"
        # снимем кавычки, если есть
        if (len(u) >= 2) and ((u[0] == u[-1] == '"') or (u[0] == u[-1] == "'")):
            u = u[1:-1].strip()
        if u.lower() in ("null", "none"):
            return None
        return u

    def _ok(self):
        name = self.e_name.get().strip()
        if not name:
            messagebox.showerror("Ошибка", "Имя правила не может быть пустым.")
            return

        types_raw = self.e_types.get().strip()
        types = [t.strip() for t in types_raw.split(",") if t.strip()]
        if not types:
            messagebox.showerror("Ошибка", "Нужно указать хотя бы один тип события.")
            return

        users_raw = self.e_users.get().strip()
        users: List[Any] = []
        if users_raw:
            for u in users_raw.split(","):
                norm = self._normalize_user_token(u)
                if norm == "":
                    continue
                users.append(norm)

        comm_contains = self.e_comm.get().strip()

        msg = self._DEFAULT_MESSAGE

        rule: Dict[str, Any] = {
            "name": name,
            "enabled": bool(self.var_enabled.get()),
            "when": {"event_type": types},
            "action": {"internal": True},
            "message": msg
        }
        if users:
            rule["when"]["user"] = users
        if comm_contains:
            rule["when"]["comm_contains"] = comm_contains

        self._result = rule
        self.destroy()

    def result(self) -> Optional[Dict[str, Any]]:
        return self._result


# -------------------- main app --------------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("AuditMon — аудит и мониторинг Linux")
        self.geometry("1250x760")

        self.cfg_path = os.environ.get("AUDITMON_CONFIG") or str(Path(__file__).with_name("config.json"))
        self.cfg = load_config(self.cfg_path)

        if self.cfg.get("gui_auth", {}).get("enabled"):
            pwd = simpledialog.askstring("Пароль", "Введите пароль AuditMon:", show="*")
            if pwd is None or not verify_gui_password(self.cfg, pwd):
                messagebox.showerror("Ошибка", "Неверный пароль.")
                self.destroy()
                return

        self.db_path = self.cfg["db_path"]

        self.conn = sqlite3.connect(self.db_path, timeout=30, check_same_thread=False, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        try:
            self.conn.execute("PRAGMA busy_timeout=5000;")
            self.conn.execute("PRAGMA journal_mode=WAL;")
        except Exception:
            pass

        self._applied_query = ""
        self._applied_from_date = ""
        self._applied_from_time = ""
        self._applied_to_date = ""
        self._applied_to_time = ""

        self._last_alert_max_id = 0
        self._alerts_badge_base = "Оповещения"
        self._rules: List[Dict[str, Any]] = list((self.cfg.get("alerts") or {}).get("rules") or [])

        self._build_ui()
        self._refresh_events_from_applied(show_errors=False)
        self._refresh_alerts()

        self.after(2000, self._poll_alert_badge)
        self.after(2000, self._poll_events_autorefresh)

    # ---------------- UI ----------------

    def _build_ui(self):
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill="both", expand=True)

        self.tab_events = ttk.Frame(self.nb)
        self.tab_alerts = ttk.Frame(self.nb)
        self.tab_reports = ttk.Frame(self.nb)
        self.tab_settings = ttk.Frame(self.nb)

        self.nb.add(self.tab_events, text="События")
        self.nb.add(self.tab_alerts, text=self._alerts_badge_base)
        self.nb.add(self.tab_reports, text="Отчеты")
        self.nb.add(self.tab_settings, text="Настройки")

        self._build_events_tab()
        self._build_alerts_tab()
        self._build_reports_tab()
        self._build_settings_tab()

    # ---------------- EVENTS ----------------

    def _build_events_tab(self):
        top = ttk.Frame(self.tab_events, padding=(10, 10))
        top.pack(fill="x")

        ttk.Label(top, text="Поиск:").grid(row=0, column=0, sticky="w")
        self.f_query = ttk.Entry(top, width=110)
        self.f_query.grid(row=0, column=1, columnspan=5, sticky="we", padx=(8, 8))
        top.columnconfigure(1, weight=1)

        ttk.Button(top, text="Применить", command=self._apply_filters).grid(row=0, column=6, sticky="e", padx=(8, 0))
        ttk.Button(top, text="Сброс", command=self._reset_filters).grid(row=0, column=7, sticky="w", padx=(8, 0))

        row1 = ttk.Frame(top)
        row1.grid(row=1, column=0, columnspan=8, sticky="we", pady=(10, 0))
        row1.columnconfigure(0, weight=1)
        row1.columnconfigure(1, weight=1)

        left = ttk.Frame(row1)
        right = ttk.Frame(row1)
        left.grid(row=0, column=0, sticky="w")
        right.grid(row=0, column=1, sticky="e")

        ttk.Label(left, text="С:").grid(row=0, column=0, sticky="w")
        ttk.Label(left, text="дата").grid(row=0, column=1, sticky="w", padx=(10, 4))
        self.f_from_date = ttk.Entry(left, width=14)
        self.f_from_date.grid(row=0, column=2, sticky="w", padx=(0, 10))
        ttk.Label(left, text="время").grid(row=0, column=3, sticky="w", padx=(0, 4))
        self.f_from_time = ttk.Entry(left, width=10)
        self.f_from_time.grid(row=0, column=4, sticky="w")

        ttk.Label(right, text="По:").grid(row=0, column=0, sticky="w")
        ttk.Label(right, text="дата").grid(row=0, column=1, sticky="w", padx=(10, 4))
        self.f_to_date = ttk.Entry(right, width=14)
        self.f_to_date.grid(row=0, column=2, sticky="w", padx=(0, 10))
        ttk.Label(right, text="время").grid(row=0, column=3, sticky="w", padx=(0, 4))
        self.f_to_time = ttk.Entry(right, width=10)
        self.f_to_time.grid(row=0, column=4, sticky="w")

        cols = ("time", "type", "user", "pid", "comm", "details")
        self.tree = ttk.Treeview(self.tab_events, columns=cols, show="headings")
        for c, w in [("time", 170), ("type", 190), ("user", 120), ("pid", 90), ("comm", 180), ("details", 520)]:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=w, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.tree.bind("<Double-1>", self._show_event_details)

    def _apply_filters(self):
        q = self.f_query.get().strip()
        fd = self.f_from_date.get().strip()
        ft = self.f_from_time.get().strip()
        td = self.f_to_date.get().strip()
        tt = self.f_to_time.get().strip()

        if not self._validate_filters(q, fd, ft, td, tt, show_errors=True):
            return

        self._applied_query = q
        self._applied_from_date = fd
        self._applied_from_time = ft
        self._applied_to_date = td
        self._applied_to_time = tt

        self._refresh_events_from_applied(show_errors=False)

    def _reset_filters(self):
        self.f_query.delete(0, "end")
        for e in (self.f_from_date, self.f_from_time, self.f_to_date, self.f_to_time):
            e.delete(0, "end")

        self._applied_query = ""
        self._applied_from_date = ""
        self._applied_from_time = ""
        self._applied_to_date = ""
        self._applied_to_time = ""

        self._refresh_events_from_applied(show_errors=False)

    def _validate_filters(self, q: str, fd: str, ft: str, td: str, tt: str, show_errors: bool) -> bool:
        ts_from, err1 = _to_ms(fd, ft, (0, 0, 0))
        ts_to, err2 = _to_ms(td, tt, (23, 59, 59))
        if err1 or err2:
            if show_errors:
                messagebox.showerror("Ошибка", "Некорректный запрос.")
            return False
        if ts_from is not None and ts_to is not None and ts_to < ts_from:
            if show_errors:
                messagebox.showerror("Ошибка", "Некорректный запрос.")
            return False

        q_sql, q_args, ek, ed = _where_from_query(q)
        if ek == "unknown_key":
            if show_errors:
                allowed = ", ".join(sorted(_ALLOWED_KEYS))
                messagebox.showerror("Ошибка", f"Неизвестный ключ. Доступные: {allowed}")
            return False
        if ek == "bad":
            if show_errors:
                messagebox.showerror("Ошибка", "Некорректный запрос.")
            return False

        return True

    def _refresh_events_from_applied(self, show_errors: bool):
        q = self._applied_query
        fd, ft = self._applied_from_date, self._applied_from_time
        td, tt = self._applied_to_date, self._applied_to_time

        ts_from, err1 = _to_ms(fd, ft, (0, 0, 0))
        ts_to, err2 = _to_ms(td, tt, (23, 59, 59))
        if err1 or err2:
            if show_errors:
                messagebox.showerror("Ошибка", "Некорректный запрос.")
            return
        if ts_from is not None and ts_to is not None and ts_to < ts_from:
            if show_errors:
                messagebox.showerror("Ошибка", "Некорректный запрос.")
            return

        where: List[str] = []
        args: List[Any] = []

        if ts_from is not None:
            where.append("ts_ms >= ?")
            args.append(ts_from)
        if ts_to is not None:
            where.append("ts_ms <= ?")
            args.append(ts_to)

        q_sql, q_args, ek, ed = _where_from_query(q)
        if ek == "unknown_key":
            if show_errors:
                allowed = ", ".join(sorted(_ALLOWED_KEYS))
                messagebox.showerror("Ошибка", f"Неизвестный ключ. Доступные: {allowed}")
            return
        if ek == "bad":
            if show_errors:
                messagebox.showerror("Ошибка", "Некорректный запрос.")
            return
        if q_sql:
            where.append(q_sql)
            args.extend(q_args)

        sql = "SELECT id, ts_ms, event_type, user, pid, comm, details_json FROM events"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY ts_ms DESC LIMIT 2000;"

        try:
            rows = self.conn.execute(sql, args).fetchall()
        except sqlite3.Error:
            if show_errors:
                messagebox.showerror("Ошибка", "Некорректный запрос.")
            return

        for item in self.tree.get_children():
            self.tree.delete(item)

        for r in rows:
            details = (r["details_json"] or "")[:220].replace("\n", " ")
            self.tree.insert("", "end", iid=str(r["id"]), values=(
                _fmt_ts(int(r["ts_ms"])),
                r["event_type"],
                r["user"] if r["user"] is not None else "null",
                r["pid"] if r["pid"] is not None else "null",
                r["comm"] if r["comm"] is not None else "null",
                details
            ))

    def _poll_events_autorefresh(self):
        if (not self._applied_from_date and not self._applied_from_time
                and not self._applied_to_date and not self._applied_to_time):
            self._refresh_events_from_applied(show_errors=False)

        self.after(2000, self._poll_events_autorefresh)

    def _show_event_details(self, _evt=None):
        sel = self.tree.selection()
        if not sel:
            return
        eid = int(sel[0])
        row = self.conn.execute("SELECT * FROM events WHERE id = ?;", (eid,)).fetchone()
        if not row:
            return

        w = tk.Toplevel(self)
        w.title(f"Событие #{eid}")
        w.geometry("950x520")
        txt = tk.Text(w, wrap="word")
        txt.pack(fill="both", expand=True)

        obj = dict(row)

        # details_json хранится как строка JSON -> превращаем в dict для красивого вывода
        raw_details = obj.get("details_json") or "{}"
        try:
            obj["details"] = json.loads(raw_details)  # вложенный объект
            obj.pop("details_json", None)  # убираем строковую версию, чтобы не было \n
        except Exception:
            # если вдруг там невалидный JSON — оставим как есть, но без краша
            obj["details"] = raw_details
            obj.pop("details_json", None)

        txt.insert("1.0", json.dumps(obj, ensure_ascii=False, indent=2))
        txt.configure(state="disabled")

    # ---------------- ALERTS ----------------

    def _build_alerts_tab(self):
        top = ttk.Frame(self.tab_alerts, padding=(10, 8))
        top.pack(fill="x")

        ttk.Button(top, text="Обновить", command=self._refresh_alerts).pack(side="left")
        ttk.Button(top, text="Отметить прочитанным", command=self._mark_alert_read).pack(side="left", padx=8)
        ttk.Button(top, text="Отметить ВСЕ прочитанным", command=self._mark_all_alerts_read).pack(side="left", padx=8)

        cols = ("time", "rule", "message", "read")
        self.alert_tree = ttk.Treeview(self.tab_alerts, columns=cols, show="headings")
        for c, w in [("time", 170), ("rule", 190), ("message", 720), ("read", 70)]:
            self.alert_tree.heading(c, text=c)
            self.alert_tree.column(c, width=w, anchor="w")
        self.alert_tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.alert_tree.bind("<Double-1>", self._open_alert)

    def _refresh_alerts(self):
        try:
            rows = self.conn.execute(
                "SELECT id, ts_ms, rule_name, message, is_read FROM alerts ORDER BY ts_ms DESC LIMIT 2000;"
            ).fetchall()
        except sqlite3.Error as e:
            messagebox.showerror("Ошибка БД", str(e))
            return

        for item in self.alert_tree.get_children():
            self.alert_tree.delete(item)

        max_id = self._last_alert_max_id
        for r in rows:
            rid = int(r["id"])
            if rid > max_id:
                max_id = rid
            self.alert_tree.insert("", "end", iid=str(rid), values=(
                _fmt_ts(int(r["ts_ms"])),
                r["rule_name"],
                (r["message"] or "")[:260].replace("\n", " "),
                "yes" if r["is_read"] else "no"
            ))

        self._last_alert_max_id = max_id
        self._update_alert_badge()

    def _mark_alert_read(self):
        sel = self.alert_tree.selection()
        if not sel:
            return
        ids = [int(x) for x in sel]
        try:
            self.conn.executemany("UPDATE alerts SET is_read=1 WHERE id=?;", [(i,) for i in ids])
        except sqlite3.Error as e:
            messagebox.showerror("Ошибка БД", str(e))
            return
        self._refresh_alerts()

    def _mark_all_alerts_read(self):
        try:
            self.conn.execute("UPDATE alerts SET is_read=1 WHERE is_read=0;")
        except sqlite3.Error as e:
            messagebox.showerror("Ошибка БД", str(e))
            return
        self._refresh_alerts()

    def _open_alert(self, _evt=None):
        sel = self.alert_tree.selection()
        if not sel:
            return
        aid = int(sel[0])
        row = self.conn.execute("SELECT * FROM alerts WHERE id=?;", (aid,)).fetchone()
        if not row:
            return

        try:
            self.conn.execute("UPDATE alerts SET is_read=1 WHERE id=?;", (aid,))
        except sqlite3.Error:
            pass

        w = tk.Toplevel(self)
        w.title(f"Оповещение #{aid}")
        w.geometry("850x340")
        txt = tk.Text(w, wrap="word")
        txt.pack(fill="both", expand=True)
        txt.insert("1.0", f"Время: {_fmt_ts(int(row['ts_ms']))}\nПравило: {row['rule_name']}\n\n{row['message']}")
        txt.configure(state="disabled")

        self._refresh_alerts()

    def _update_alert_badge(self):
        try:
            unread = self.conn.execute("SELECT COUNT(1) AS c FROM alerts WHERE is_read=0;").fetchone()
            cnt = int(unread["c"]) if unread else 0
        except Exception:
            cnt = 0

        if cnt > 0:
            self.nb.tab(self.tab_alerts, text=f"{self._alerts_badge_base}  ● {cnt}")
        else:
            self.nb.tab(self.tab_alerts, text=self._alerts_badge_base)

    def _poll_alert_badge(self):
        try:
            row = self.conn.execute("SELECT MAX(id) AS mx FROM alerts;").fetchone()
            mx = int(row["mx"] or 0)
        except Exception:
            mx = self._last_alert_max_id

        if mx > self._last_alert_max_id:
            self._refresh_alerts()
        else:
            self._update_alert_badge()

        self.after(2000, self._poll_alert_badge)

    # ---------------- REPORTS ----------------

    def _build_reports_tab(self):
        frm = ttk.Frame(self.tab_reports, padding=(10, 10))
        frm.pack(fill="x")

        ttk.Label(frm, text="Период С (дата)").grid(row=0, column=0, sticky="w")
        self.r_from_date = ttk.Entry(frm, width=14)
        self.r_from_date.grid(row=0, column=1, sticky="w", padx=(8, 16))
        self.r_from_date.insert(0, time.strftime("%Y-%m-%d"))

        ttk.Label(frm, text="С (время)").grid(row=0, column=2, sticky="w")
        self.r_from_time = ttk.Entry(frm, width=10)
        self.r_from_time.grid(row=0, column=3, sticky="w", padx=(8, 16))
        self.r_from_time.insert(0, "00:00:00")

        ttk.Label(frm, text="По (дата)").grid(row=0, column=4, sticky="w")
        self.r_to_date = ttk.Entry(frm, width=14)
        self.r_to_date.grid(row=0, column=5, sticky="w", padx=(8, 16))
        self.r_to_date.insert(0, time.strftime("%Y-%m-%d"))

        ttk.Label(frm, text="По (время)").grid(row=0, column=6, sticky="w")
        self.r_to_time = ttk.Entry(frm, width=10)
        self.r_to_time.grid(row=0, column=7, sticky="w", padx=(8, 16))
        self.r_to_time.insert(0, time.strftime("%H:%M:%S"))

        ttk.Button(frm, text="Сгенерировать HTML-отчет", command=self._gen_report).grid(row=0, column=8, sticky="w")

        self.report_info = ttk.Label(self.tab_reports, text="", foreground="#333")
        self.report_info.pack(fill="x", padx=10)

    def _gen_report(self):
        ts_from, e1 = _to_ms(self.r_from_date.get(), self.r_from_time.get(), (0, 0, 0))
        ts_to, e2 = _to_ms(self.r_to_date.get(), self.r_to_time.get(), (23, 59, 59))
        if e1 or e2 or ts_from is None or ts_to is None or ts_to < ts_from:
            messagebox.showerror("Ошибка", "Некорректный период.")
            return

        out = filedialog.asksaveasfilename(
            title="Сохранить отчет",
            defaultextension=".html",
            filetypes=[("HTML", "*.html")]
        )
        if not out:
            return
        try:
            path = generate_html_report(self.db_path, out, ts_from, ts_to)
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))
            return
        self.report_info.config(text=f"Отчет сохранен: {path}")
        try:
            webbrowser.open(f"file://{path}")
        except Exception:
            pass

    # ---------------- SETTINGS ----------------

    def _build_settings_tab(self):
        frm = ttk.Frame(self.tab_settings, padding=(10, 10))
        frm.pack(fill="both", expand=True)

        frm.columnconfigure(0, weight=1)
        frm.columnconfigure(1, weight=1)
        frm.rowconfigure(0, weight=1)
        frm.rowconfigure(1, weight=1)

        box1 = ttk.LabelFrame(frm, text="Наблюдаемые пути", padding=8)
        box1.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        box1.rowconfigure(0, weight=1)
        box1.columnconfigure(0, weight=1)

        self.paths = tk.Listbox(box1, height=10)
        self.paths.grid(row=0, column=0, columnspan=2, sticky="nsew", padx=4, pady=4)

        for p in self.cfg.get("inotify_paths", []):
            self.paths.insert("end", p)

        ttk.Button(box1, text="Добавить", command=self._add_path).grid(row=1, column=0, sticky="w", padx=4, pady=(0, 4))
        ttk.Button(box1, text="Удалить", command=self._del_path).grid(row=1, column=1, sticky="e", padx=4, pady=(0, 4))

        self.var_hash_paths = tk.BooleanVar(value=bool((self.cfg.get("privacy") or {}).get("hash_paths")))
        ttk.Checkbutton(frm, text="Хэшировать пути", variable=self.var_hash_paths).grid(
            row=2, column=0, sticky="w", pady=(8, 0)
        )

        box_rules = ttk.LabelFrame(frm, text="Правила оповещений", padding=8)
        box_rules.grid(row=1, column=0, columnspan=2, sticky="nsew", pady=(10, 0))
        box_rules.rowconfigure(0, weight=1)
        box_rules.columnconfigure(0, weight=1)

        cols = ("name", "enabled", "types", "users", "comm")
        self.rules_tree = ttk.Treeview(box_rules, columns=cols, show="headings", height=7)
        for c, w in [("name", 220), ("enabled", 90), ("types", 420), ("users", 220), ("comm", 220)]:
            self.rules_tree.heading(c, text=c)
            self.rules_tree.column(c, width=w, anchor="w")
        self.rules_tree.grid(row=0, column=0, columnspan=5, sticky="nsew", padx=4, pady=4)

        ttk.Button(box_rules, text="Добавить правило", command=self._rule_add).grid(row=1, column=0, sticky="w", padx=4, pady=(0, 4))
        ttk.Button(box_rules, text="Изменить", command=self._rule_edit).grid(row=1, column=1, sticky="w", padx=4, pady=(0, 4))
        ttk.Button(box_rules, text="Удалить", command=self._rule_del).grid(row=1, column=2, sticky="w", padx=4, pady=(0, 4))

        self._refresh_rules_table()

        box4 = ttk.LabelFrame(frm, text="Защита GUI", padding=8)
        box4.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(10, 0))
        self.var_gui_auth = tk.BooleanVar(value=bool((self.cfg.get("gui_auth") or {}).get("enabled")))
        ttk.Checkbutton(box4, text="Требовать пароль при запуске GUI", variable=self.var_gui_auth).pack(side="left", padx=8, pady=6)
        ttk.Button(box4, text="Установить/сменить пароль", command=self._set_password).pack(side="left", padx=8)

        ttk.Button(frm, text="Сохранить настройки", command=self._save_settings).grid(row=4, column=0, sticky="w", pady=12)

    def _refresh_rules_table(self):
        for item in self.rules_tree.get_children():
            self.rules_tree.delete(item)

        for idx, r in enumerate(self._rules):
            when = r.get("when") or {}
            types = ", ".join([str(x) for x in (when.get("event_type") or [])])
            users = when.get("user") or []
            users_s = ", ".join(["null" if u is None else str(u) for u in users]) if users else ""
            comm = str(when.get("comm_contains") or "")
            self.rules_tree.insert("", "end", iid=str(idx), values=(
                r.get("name", ""),
                "yes" if _safe_bool(r.get("enabled", True)) else "no",
                types,
                users_s,
                comm
            ))

    def _rule_add(self):
        dlg = RuleDialog(self, None)
        self.wait_window(dlg)
        r = dlg.result()
        if r:
            self._rules.append(r)
            self._refresh_rules_table()

    def _rule_edit(self):
        sel = self.rules_tree.selection()
        if not sel:
            return
        idx = int(sel[0])
        dlg = RuleDialog(self, self._rules[idx])
        self.wait_window(dlg)
        r = dlg.result()
        if r:
            self._rules[idx] = r
            self._refresh_rules_table()

    def _rule_del(self):
        sel = self.rules_tree.selection()
        if not sel:
            return
        idx = int(sel[0])
        if messagebox.askyesno("Удаление", f"Удалить правило '{self._rules[idx].get('name','')}'?"):
            self._rules.pop(idx)
            self._refresh_rules_table()

    def _add_path(self):
        p = filedialog.askdirectory(title="Выберите папку для наблюдения")
        if not p:
            return
        self.paths.insert("end", p)

    def _del_path(self):
        sel = self.paths.curselection()
        if not sel:
            return
        for i in reversed(sel):
            self.paths.delete(i)

    def _set_password(self):
        p1 = simpledialog.askstring("Пароль", "Новый пароль:", show="*")
        if not p1:
            return
        p2 = simpledialog.askstring("Пароль", "Повторите пароль:", show="*")
        if p1 != p2:
            messagebox.showerror("Ошибка", "Пароли не совпадают.")
            return
        set_gui_password(self.cfg, p1)
        self.var_gui_auth.set(True)
        messagebox.showinfo("OK", "Пароль установлен.")

    def _save_settings(self):
        paths = [self.paths.get(i) for i in range(self.paths.size())]
        self.cfg["inotify_paths"] = paths

        self.cfg.setdefault("privacy", {})
        self.cfg["privacy"]["hash_paths"] = bool(self.var_hash_paths.get())

        self.cfg.setdefault("alerts", {})
        self.cfg["alerts"]["enabled"] = True
        self.cfg["alerts"]["rules"] = self._rules

        self.cfg.setdefault("gui_auth", {})
        self.cfg["gui_auth"]["enabled"] = bool(self.var_gui_auth.get())

        try:
            save_config(self.cfg, self.cfg_path)
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))
            return

        self._refresh_rules_table()
        messagebox.showinfo("OK", "Настройки сохранены.\nПерезапусти демон, чтобы правила/пути применились.")


# -------------------- main --------------------

def main():
    app = App()
    try:
        app.mainloop()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
