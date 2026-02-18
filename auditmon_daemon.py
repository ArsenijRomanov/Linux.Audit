from __future__ import annotations

import os
import re
import json
import time
import queue
import pwd
import threading
import signal
import subprocess
import ctypes
import ctypes.util
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple

from auditmon_common import (
    load_config, init_db, now_ms, Event, insert_event, insert_alert,
    rotate_db_if_needed, hash_if_needed
)
from inotify_ctypes import InotifyWatcher
import ptrace_x86_64 as px

O_CREAT = 0o100  # open(2) flag

STOP = threading.Event()

libc_path = ctypes.util.find_library("c")
libc = ctypes.CDLL(libc_path, use_errno=True) if libc_path else None

PR_SET_KEEPCAPS = 8

CAP_SYS_PTRACE = 19 # право трасировать чужие процессы
CAP_DAC_READ_SEARCH = 2 # право читать

# capset structs (linux/capability.h)
class __user_cap_header_struct(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]

class __user_cap_data_struct(ctypes.Structure):
    _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32), ("inheritable", ctypes.c_uint32)]

_LINUX_CAPABILITY_VERSION_3 = 0x20080522

# ==== блок capabilities - сброс прав с root до CAP_SYS_PTRACE и CAP_DAC_READ_SEARCH ====
def _cap_mask(cap: int) -> int:
    return 1 << (cap % 32)

def _cap_index(cap: int) -> int:
    return cap // 32

def _capset(keep: List[int]) -> None:
    if libc is None:
        return
    hdr = __user_cap_header_struct()
    hdr.version = _LINUX_CAPABILITY_VERSION_3
    hdr.pid = 0
    data = (__user_cap_data_struct * 2)()
    # zero all
    for i in range(2):
        data[i].effective = 0
        data[i].permitted = 0
        data[i].inheritable = 0
    for cap in keep:
        idx = _cap_index(cap)
        m = _cap_mask(cap)
        data[idx].effective |= m
        data[idx].permitted |= m
    res = libc.capset(ctypes.byref(hdr), ctypes.byref(data))
    if res != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))

def drop_privileges_keep_caps(cfg: Dict[str, Any], ev_q: "queue.Queue[RawEvent]", cfg_path: str) -> None:
    sec = cfg.get("security", {}) or {}
    if not sec.get("drop_privileges", True):
        return
    if os.geteuid() != 0:
        return
    user = (sec.get("run_user") or "").strip()
    if not user:
        # drop to owner of config file (best effort)
        try:
            st = os.stat(cfg_path)
            user = pwd.getpwuid(st.st_uid).pw_name
        except Exception:
            user = ""
    if not user:
        return

    # resolve user
    try:
        pw = pwd.getpwnam(user)
    except KeyError:
        # record and continue as root (best effort)
        try:
            ev_q.put_nowait(RawEvent("SECURITY_WARN", os.getpid(), {"message": f"user '{user}' not found; running as root"}))
        except Exception:
            pass
        return

    keep = []
    keep_names = set(sec.get("keep_caps") or [])
    if "SYS_PTRACE" in keep_names:
        keep.append(CAP_SYS_PTRACE)
    if "DAC_READ_SEARCH" in keep_names:
        keep.append(CAP_DAC_READ_SEARCH)

    try:
        # keep caps after setuid
        if libc is not None:
            if libc.prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0:
                err = ctypes.get_errno()
                raise OSError(err, os.strerror(err))

        # drop groups
        try:
            os.setgroups([])
        except Exception:
            pass

        os.setgid(pw.pw_gid)
        os.setuid(pw.pw_uid)

        # apply minimal caps
        _capset(keep)

        try:
            ev_q.put_nowait(RawEvent("SECURITY_DROP_PRIVS", os.getpid(), {"run_user": user, "uid": pw.pw_uid, "gid": pw.pw_gid, "kept_caps": list(keep_names)}))
        except Exception:
            pass
    except Exception as e:
        # if anything fails: record and keep running (but may still be root)
        try:
            ev_q.put_nowait(RawEvent("SECURITY_WARN", os.getpid(), {"message": f"drop_privileges failed: {e}"}))
        except Exception:
            pass

# ==== блок чтения /proc ====

# Перевод числового uid в имя пользователя
def _uid_to_name(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except Exception:
        return str(uid)

# Читает /proc/<pid>/status и вытаскивает:
# * uid
# * ppid
# * name
def _read_proc_status(pid: int) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    try:
        with open(f"/proc/{pid}/status", "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("Uid:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        out["uid"] = int(parts[1])
                elif line.startswith("PPid:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        out["ppid"] = int(parts[1])
                elif line.startswith("Name:"):
                    parts = line.split()
                    if len(parts) >= 2:
                        out["name"] = parts[1].strip()
    except Exception:
        pass
    return out

# Читает /proc/<pid>/comm — короткое имя процесса
def _read_proc_comm(pid: int) -> str:
    try:
        return Path(f"/proc/{pid}/comm").read_text(encoding="utf-8", errors="replace").strip()
    except Exception:
        return ""

# Читает /proc/<pid>/cmdline — аргументы запуска (например "python3 auditmon_daemon.py")
def _read_cmdline(pid: int) -> str:
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
        return raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
    except Exception:
        return ""

# Склеивает всё это в набор:
# user, uid, ppid, comm
# чтобы DBWriter мог записать это в events
def _event_user_pid_comm(pid: int) -> Tuple[Optional[str], Optional[int], Optional[int], Optional[str]]:
    st = _read_proc_status(pid)
    uid = st.get("uid")
    user = _uid_to_name(uid) if uid is not None else None
    ppid = st.get("ppid")
    comm = st.get("name") or _read_proc_comm(pid) or None
    return user, uid, ppid, comm

@dataclass
class RawEvent:   # сырой объект события, создаваемый всеми источниками событий
    event_type: str
    pid: Optional[int]
    details: Dict[str, Any]

# ==== Блок БД ====
# поток
# пишет в бд
# берёт RawEvent из очереди
# добавляет сведения о процессе из /proc (user/uid/ppid/comm)
# пишет строку в events
# проверяет rules и пишет alerts (внутренние уведомления)
# делает ротацию БД по размеру
class DBWriter(threading.Thread):
    # создаёт / инициализирует БД
    # открывает sqlite соединение
    # запоминает настройки ротации
    # сохраняет очередь событий
    def __init__(self, cfg: Dict[str, Any], q: "queue.Queue[RawEvent]"):
        super().__init__(daemon=True)
        self.cfg = cfg
        self.q = q
        self.db_path = cfg["db_path"]
        self.archive_dir = cfg["archive_dir"]
        self.rotate_max_mb = int(cfg.get("rotate_max_mb", 64))
        init_db(self.db_path)
        self.conn = sqlite3.connect(self.db_path, timeout=30, isolation_level=None, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA synchronous=NORMAL;")
        self._last_rotate_check = time.time()

    # Если прошло достаточно времени:
    # проверяет размер файла БД,
    # если больше порога => архивирует и создаёт новую БД,
    # пишет событие JOURNAL_ROTATE
    def _maybe_rotate(self) -> None:
        if time.time() - self._last_rotate_check < 5:
            return
        self._last_rotate_check = time.time()
        try:
            self.conn.execute("PRAGMA wal_checkpoint(FULL);")
            self.conn.close()
        except Exception:
            pass
        archive = rotate_db_if_needed(self.db_path, self.archive_dir, self.rotate_max_mb)
        # reopen
        self.conn = sqlite3.connect(self.db_path, timeout=30, isolation_level=None, check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA synchronous=NORMAL;")
        if archive:
            # record rotation event
            ev = Event(
                ts_ms=now_ms(),
                event_type="JOURNAL_ROTATE",
                user=None, uid=None, pid=None, ppid=None, comm=None,
                details_json=json.dumps({"archive": archive}, ensure_ascii=False)
            )
            insert_event(self.conn, ev)

    # Проверяет, подходит ли событие под правило:
    # * тип события
    # * пользователь
    # * подстрока в comm
    # * regex по details_json
    def _match_rule(self, rule: Dict[str, Any], ev_row: Dict[str, Any]) -> bool:
        when = rule.get("when", {})
        # event_type
        if "event_type" in when:
            allowed = set(when.get("event_type") or [])
            if allowed and ev_row.get("event_type") not in allowed:
                return False
        if "user" in when:
            allowed = set(when.get("user") or [])
            if allowed and ev_row.get("user") not in allowed:
                return False
        if "comm_contains" in when:
            needle = str(when.get("comm_contains") or "")
            if needle and needle not in (ev_row.get("comm") or ""):
                return False
        if "details_regex" in when:
            pat = when.get("details_regex")
            if pat:
                try:
                    if not re.search(pat, ev_row.get("details_json","")):
                        return False
                except re.error:
                    return False
        return True

    # Подставляет {event_type}, {user}, {pid}, {comm} и т.п.в строку уведомления
    def _render_message(self, template: str, ev_row: Dict[str, Any], details: Dict[str, Any]) -> str:
        ctx = dict(ev_row)
        ctx.update(details)
        try:
            return template.format(**ctx)
        except Exception:
            return template

    # Если правило совпало и internal = True: создаёт запись в таблице alerts
    def _handle_alerts(self, event_id: int, ev_row: Dict[str, Any], details: Dict[str, Any]) -> None:
        alerts_cfg = self.cfg.get("alerts", {})
        if not alerts_cfg.get("enabled", True):
            return
        rules = alerts_cfg.get("rules") or []
        for rule in rules:
            if not rule or not rule.get("enabled", True):
                continue
            if not self._match_rule(rule, ev_row):
                continue
            action = rule.get("action", {})
            msg_tpl = rule.get("message") or "Событие: {event_type} pid={pid} user={user}"
            msg = self._render_message(msg_tpl, ev_row, details)

            if action.get("internal", True):
                insert_alert(self.conn, now_ms(), rule.get("name", "rule"), event_id, msg)

    # Главный цикл:
    # * берёт событие из очереди
    # * добавляет user / uid / ppid / comm
    # * пишет в events
    # * запускает _handle_alerts
    # * иногда делает _maybe_rotate
    def run(self) -> None:
        while not STOP.is_set():
            try:
                raw = self.q.get(timeout=0.5)
            except queue.Empty:
                self._maybe_rotate()
                continue

            ts = now_ms()
            details = raw.details or {}
            pid = raw.pid
            user = uid = ppid = comm = None
            if pid is not None:
                user, uid, ppid, comm = _event_user_pid_comm(pid)

            # privacy: hash file paths if enabled
            for k in ("path", "old_path", "new_path"):
                if k in details and isinstance(details[k], str):
                    details[k] = hash_if_needed(self.cfg, details[k])

            ev = Event(
                ts_ms=ts,
                event_type=raw.event_type,
                user=user, uid=uid, pid=pid, ppid=ppid, comm=comm,
                details_json=json.dumps(details, ensure_ascii=False)
            )
            try:
                event_id = insert_event(self.conn, ev)
            except sqlite3.Error:
                # try reopening
                try:
                    self.conn.close()
                except Exception:
                    pass
                init_db(self.db_path)
                self.conn = sqlite3.connect(self.db_path, timeout=30, isolation_level=None, check_same_thread=False)
                self.conn.execute("PRAGMA journal_mode=WAL;")
                self.conn.execute("PRAGMA synchronous=NORMAL;")
                event_id = insert_event(self.conn, ev)

            ev_row = {
                "event_id": event_id,
                "ts_ms": ts,
                "event_type": raw.event_type,
                "user": user,
                "uid": uid,
                "pid": pid,
                "ppid": ppid,
                "comm": comm,
                "details_json": ev.details_json
            }
            try:
                self._handle_alerts(event_id, ev_row, details)
            except Exception:
                pass

            self._maybe_rotate()

# поток
# периодически смотрит /proc и находит новые PID, которые ещё не трассируются. Кладёт их в attach_q
class ProcScanner(threading.Thread):
    def __init__(self, interval: float, out_queue: "queue.Queue[int]"):
        super().__init__(daemon=True)
        self.interval = interval
        self.out = out_queue
        self.known: set[int] = set()

    # Каждую секунду:
    # * читает список PID из / proc
    # * убирает уже известные
    # * добавляет новые в очередь attach-а
    def run(self) -> None:
        while not STOP.is_set():
            pids = []
            try:
                for name in os.listdir("/proc"):
                    if name.isdigit():
                        pids.append(int(name))
            except Exception:
                time.sleep(self.interval)
                continue
            pids.sort()
            for pid in pids:
                if pid == os.getpid():
                    continue
                if pid in self.known:
                    continue
                # ignore kernel threads: cmdline empty and comm like [kthreadd]
                cmd = _read_cmdline(pid)
                comm = _read_proc_comm(pid)
                if (not cmd) and comm.startswith("[") and comm.endswith("]"):
                    self.known.add(pid)
                    continue
                self.known.add(pid)
                try:
                    self.out.put_nowait(pid)
                except queue.Full:
                    pass
            time.sleep(self.interval)

@dataclass
class TraceState:    # состояние трассировки одного процесса
    in_syscall: bool = False
    last_syscall: int = -1
    args: Tuple[int, int, int, int, int, int] = (0,0,0,0,0,0)

# поток
# ptrace-трассировщик. Attach-ится к PID из attach_q, получает stop-события через waitpid, распознаёт syscalls
# создаёт RawEvent типа:
#   процесс: start/exit (exec/exit)
#   файлы: open/create/delete/rename
#   сеть: connect/bind/accept
class SyscallTracer(threading.Thread):
    def __init__(self, attach_queue: "queue.Queue[int]", ev_queue: "queue.Queue[RawEvent]"):
        super().__init__(daemon=True)
        self.attach_q = attach_queue
        self.ev_q = ev_queue
        self.traced: Dict[int, TraceState] = {}
        self._attach_lock = threading.Lock()

    def _emit(self, et: str, pid: int, details: Dict[str, Any]) -> None:
        try:
            self.ev_q.put_nowait(RawEvent(et, pid, details))
        except queue.Full:
            pass

    def _try_attach(self, pid: int) -> None:
        # already traced
        if pid in self.traced:
            return
        # may fail due to permissions or short-lived process
        try:
            px.attach(pid)
        except Exception:
            return
        try:
            got, status = px.waitpid_pid(pid, 0)
            if got != pid:
                return
            px.set_options(pid)
            self.traced[pid] = TraceState(in_syscall=False)
            # start syscall tracing
            px.syscall(pid, 0)
        except Exception:
            try:
                px.detach(pid)
            except Exception:
                pass
            self.traced.pop(pid, None)

    def _handle_syscall(self, pid: int, entering: bool) -> None:
        st = self.traced.get(pid)
        if not st:
            return
        regs = px.get_regs(pid)
        if entering:
            st.in_syscall = True
            st.last_syscall = int(regs.orig_rax)
            st.args = (int(regs.rdi), int(regs.rsi), int(regs.rdx), int(regs.r10), int(regs.r8), int(regs.r9))

            sc = st.last_syscall
            a1,a2,a3,a4,a5,a6 = st.args

            if sc in (px.SYS_execve, px.SYS_execveat):
                if sc == px.SYS_execve:
                    filename = px.read_cstring(pid, a1, 512)
                    argv = px.read_argv(pid, a2)
                    self._emit("PROCESS_START", pid, {"exe": filename, "argv": argv})
                else:
                    # execveat(dirfd, pathname, argv, envp, flags)
                    filename = px.read_cstring(pid, a2, 512)
                    argv = px.read_argv(pid, a3)
                    self._emit("PROCESS_START", pid, {"exe": filename, "argv": argv, "execveat": True})
                return

            if sc in (px.SYS_exit, px.SYS_exit_group):
                code = a1
                self._emit("PROCESS_EXIT", pid, {"exit_code": int(code), "syscall": sc})
                return

            if sc == px.SYS_connect:
                sockaddr = px.read_sockaddr(pid, a2, a3)
                self._emit("NET_CONNECT_ATTEMPT", pid, {"fd": int(a1), "remote": sockaddr})
                return

            if sc == px.SYS_bind:
                sockaddr = px.read_sockaddr(pid, a2, a3)
                self._emit("NET_BIND_ATTEMPT", pid, {"fd": int(a1), "local": sockaddr})
                return

            if sc in (px.SYS_accept, px.SYS_accept4):
                # accept fills sockaddr on exit; store pointer+len in args
                return

            if sc == px.SYS_open:
                path = px.read_cstring(pid, a1, 1024)
                flags = int(a2)
                self._emit("FILE_OPEN", pid, {"path": path, "flags": flags})
                if flags & O_CREAT:
                    self._emit("FILE_CREATE_ATTEMPT", pid, {"path": path, "flags": flags})
                return

            if sc == px.SYS_openat:
                path = px.read_cstring(pid, a2, 1024)
                flags = int(a3)
                self._emit("FILE_OPEN", pid, {"path": path, "flags": flags, "openat": True, "dirfd": int(a1)})
                if flags & O_CREAT:
                    self._emit("FILE_CREATE_ATTEMPT", pid, {"path": path, "flags": flags, "openat": True})
                return

            if sc in (px.SYS_unlink, px.SYS_unlinkat):
                path = px.read_cstring(pid, a1 if sc==px.SYS_unlink else a2, 1024)
                self._emit("FILE_DELETE_ATTEMPT", pid, {"path": path})
                return

            if sc in (px.SYS_rename, px.SYS_renameat):
                if sc == px.SYS_rename:
                    oldp = px.read_cstring(pid, a1, 1024)
                    newp = px.read_cstring(pid, a2, 1024)
                else:
                    oldp = px.read_cstring(pid, a2, 1024)
                    newp = px.read_cstring(pid, a4, 1024)
                self._emit("FILE_RENAME_ATTEMPT", pid, {"old_path": oldp, "new_path": newp})
                return
        else:
            # syscall exit: can log success/failure with return value if needed
            st.in_syscall = False
            sc = st.last_syscall
            ret = int(regs.rax & 0xffffffffffffffff)
            # Interpret negative errno in signed 64-bit
            if ret & (1<<63):
                signed_ret = ret - (1<<64)
            else:
                signed_ret = ret

            a1,a2,a3,a4,a5,a6 = st.args

            if sc == px.SYS_connect:
                self._emit("NET_CONNECT_RESULT", pid, {"ret": signed_ret})
                return

            if sc == px.SYS_bind:
                self._emit("NET_BIND_RESULT", pid, {"ret": signed_ret})
                return

            if sc in (px.SYS_accept, px.SYS_accept4):
                peer = {}
                if a2 != 0 and a3 != 0:
                    try:
                        ln = px.read_bytes(pid, a3, 4)
                        alen = int.from_bytes(ln, "little", signed=False)
                        peer = px.read_sockaddr(pid, a2, alen)
                    except Exception:
                        peer = {}
                self._emit("NET_ACCEPT", pid, {"ret_fd": signed_ret, "peer": peer})
                return

            if sc in (px.SYS_unlink, px.SYS_unlinkat):
                path = px.read_cstring(pid, a1 if sc==px.SYS_unlink else a2, 1024)
                self._emit("FILE_DELETE", pid, {"path": path, "ret": signed_ret})
                return

            if sc in (px.SYS_rename, px.SYS_renameat):
                if sc == px.SYS_rename:
                    oldp = px.read_cstring(pid, a1, 1024)
                    newp = px.read_cstring(pid, a2, 1024)
                else:
                    oldp = px.read_cstring(pid, a2, 1024)
                    newp = px.read_cstring(pid, a4, 1024)
                self._emit("FILE_RENAME", pid, {"old_path": oldp, "new_path": newp, "ret": signed_ret})
                return

            if sc in (px.SYS_open, px.SYS_openat):
                # log create success if O_CREAT used
                flags = int(a2) if sc==px.SYS_open else int(a3)
                if flags & O_CREAT:
                    path = px.read_cstring(pid, a1 if sc==px.SYS_open else a2, 1024)
                    self._emit("FILE_CREATE", pid, {"path": path, "ret_fd": signed_ret})
                return

    def run(self) -> None:
        # Try to attach to existing processes already in /proc at start
        # (best effort; scanner will add new ones later)
        while not STOP.is_set():
            # Drain attach queue first (non-blocking)
            try:
                while True:
                    pid = self.attach_q.get_nowait()
                    self._try_attach(pid)
            except queue.Empty:
                pass

            # Wait for any traced process to stop (blocking but interruptible by signals)
            try:
                pid, status = px.waitpid_any(0)
            except OSError:
                time.sleep(0.1)
                continue

            if pid <= 0:
                continue

            if px.WIFEXITED(status):
                self.traced.pop(pid, None)
                continue
            if px.WIFSIGNALED(status):
                self.traced.pop(pid, None)
                continue

            if not px.WIFSTOPPED(status):
                continue

            sig = px.WSTOPSIG(status)

            # Syscall stop
            if sig == (px.SIGTRAP | 0x80):
                st = self.traced.get(pid)
                if not st:
                    try:
                        px.syscall(pid, 0)
                    except Exception:
                        pass
                    continue
                entering = not st.in_syscall
                try:
                    self._handle_syscall(pid, entering)
                except Exception:
                    pass
                try:
                    px.syscall(pid, 0)
                except Exception:
                    self.traced.pop(pid, None)
                continue

            try:
                px.syscall(pid, sig)
            except Exception:
                self.traced.pop(pid, None)

# поток
# читает journalctl -f -o json, превращает строки journald в RawEvent("SYSLOG", ...) с rate-limit
class JournalTail(threading.Thread):
    """
    Tails system journal (journald) using `journalctl -f -o json`.
    Records entries as event_type=SYSLOG.
    """
    def __init__(self, cfg: Dict[str, Any], ev_queue: "queue.Queue[RawEvent]"):
        super().__init__(daemon=True)
        self.cfg = cfg
        self.ev_q = ev_queue
        self._p: Optional[subprocess.Popen] = None
        self._last_minute = int(time.time() // 60)
        self._count_this_minute = 0

    def run(self) -> None:
        jcfg = self.cfg.get("journal", {}) or {}
        if not jcfg.get("enabled", True):
            return
        unit = (jcfg.get("unit") or "").strip()
        max_lpm = int(jcfg.get("max_lines_per_min", 600))
        cmd = ["journalctl", "-f", "-o", "json"]
        if unit:
            cmd += ["-u", unit]
        try:
            self._p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
        except Exception:
            return

        assert self._p.stdout is not None
        for line in self._p.stdout:
            if STOP.is_set():
                break
            line = line.strip()
            if not line:
                continue
            # rate limit
            m = int(time.time() // 60)
            if m != self._last_minute:
                self._last_minute = m
                self._count_this_minute = 0
            self._count_this_minute += 1
            if self._count_this_minute > max_lpm:
                continue

            try:
                obj = json.loads(line)
            except Exception:
                continue

            # journald timestamp is in usec string
            ts_ms = None
            try:
                rt = obj.get("__REALTIME_TIMESTAMP")
                if rt:
                    ts_ms = int(int(rt) / 1000)
            except Exception:
                ts_ms = None

            details = {
                "message": obj.get("MESSAGE", ""),
                "unit": obj.get("_SYSTEMD_UNIT") or obj.get("UNIT") or "",
                "identifier": obj.get("SYSLOG_IDENTIFIER") or "",
                "priority": obj.get("PRIORITY"),
                "pid": obj.get("_PID"),
                "comm": obj.get("_COMM"),
                "exe": obj.get("_EXE"),
                "uid": obj.get("_UID"),
            }
            # Put event with pid if known (so DBWriter can resolve user/comm)
            pid = None
            try:
                pid = int(details.get("pid")) if details.get("pid") is not None else None
            except Exception:
                pid = None
            # DBWriter uses now_ms() for ts; we keep original timestamp in details
            if ts_ms is not None:
                details["journal_ts_ms"] = ts_ms

            try:
                self.ev_q.put_nowait(RawEvent("SYSLOG", pid, details))
            except queue.Full:
                pass

        try:
            if self._p:
                self._p.terminate()
        except Exception:
            pass


def map_inotify(mask: int) -> str:
    from inotify_ctypes import IN_CREATE, IN_DELETE, IN_MODIFY, IN_MOVED_FROM, IN_MOVED_TO, IN_ATTRIB, IN_CLOSE_WRITE
    if mask & IN_CREATE:
        return "FILE_CREATE"
    if mask & IN_DELETE:
        return "FILE_DELETE"
    if mask & IN_MOVED_FROM or mask & IN_MOVED_TO:
        return "FILE_MOVE"
    if mask & IN_CLOSE_WRITE:
        return "FILE_MODIFY"
    if mask & IN_MODIFY:
        return "FILE_MODIFY"
    if mask & IN_ATTRIB:
        return "FILE_ATTRIB"
    return "FILE_EVENT"


def main() -> None:
    os.umask(0o077)
    cfg_path = os.environ.get('AUDITMON_CONFIG') or str(Path(__file__).with_name('config.json'))
    cfg = load_config(cfg_path)
    # if started via sudo, ensure config.json owned by invoking user (so we can drop privileges)
    if os.geteuid() == 0 and os.environ.get('SUDO_UID') and os.environ.get('SUDO_GID'):
        try:
            uid = int(os.environ['SUDO_UID']); gid = int(os.environ['SUDO_GID'])
            os.chown(cfg_path, uid, gid)
        except Exception:
            pass

    ev_q: "queue.Queue[RawEvent]" = queue.Queue(maxsize=50_000)
    # drop privileges early (best effort), keep only minimal capabilities
    drop_privileges_keep_caps(cfg, ev_q, cfg_path)
    writer = DBWriter(cfg, ev_q)
    writer.start()

    # inotify watcher
    def on_fs(path: str, mask: int, is_dir: bool) -> None:
        et = map_inotify(mask)
        try:
            ev_q.put_nowait(RawEvent(et, None, {"path": path, "mask": mask, "is_dir": bool(is_dir)}))
        except queue.Full:
            pass

    watcher = InotifyWatcher(on_fs)
    for p in cfg.get("inotify_paths", []):
        watcher.add_watch_recursive(p)
    watcher.start()

    # journald tail
    jt = JournalTail(cfg, ev_q)
    jt.start()

    # ptrace tracer
    attach_q: "queue.Queue[int]" = queue.Queue(maxsize=200_000)
    scanner = ProcScanner(float(cfg.get("proc_scan_interval_sec", 1.0)), attach_q)
    tracer = SyscallTracer(attach_q, ev_q)

    scanner.start()
    tracer.start()

    # Log daemon start
    ev_q.put(RawEvent("DAEMON_START", os.getpid(), {"uid": os.getuid(), "euid": os.geteuid()}))

    def _sig_handler(_sig, _frm):
        STOP.set()
    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    while not STOP.is_set():
        time.sleep(0.5)

    # best effort shutdown
    ev_q.put(RawEvent("DAEMON_STOP", os.getpid(), {}))
    try:
        watcher.stop()
    except Exception:
        pass


if __name__ == "__main__":
    main()
