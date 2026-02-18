# -*- coding: utf-8 -*-
from __future__ import annotations

import ctypes
import ctypes.util
import os
import socket
import struct
from dataclasses import dataclass
from typing import Optional, Dict, Any, List, Tuple

libc_path = ctypes.util.find_library("c")
if not libc_path:
    raise RuntimeError("libc not found")
libc = ctypes.CDLL(libc_path, use_errno=True)

# ptrace requests
PTRACE_TRACEME     = 0
PTRACE_PEEKTEXT    = 1
PTRACE_PEEKDATA    = 2
PTRACE_PEEKUSER    = 3
PTRACE_POKETEXT    = 4
PTRACE_POKEDATA    = 5
PTRACE_POKEUSER    = 6
PTRACE_CONT        = 7
PTRACE_KILL        = 8
PTRACE_SINGLESTEP  = 9
PTRACE_GETREGS     = 12
PTRACE_SETREGS     = 13
PTRACE_ATTACH      = 16
PTRACE_DETACH      = 17
PTRACE_SYSCALL     = 24
PTRACE_SETOPTIONS  = 0x4200
PTRACE_GETEVENTMSG = 0x4201

# ptrace options
PTRACE_O_TRACESYSGOOD = 0x00000001
PTRACE_O_TRACEEXEC    = 0x00000010
PTRACE_O_TRACEEXIT    = 0x00000040

# waitpid flags
__WALL = 0x40000000  # wait for all children, including traced
WNOHANG = 1

# signals/stop codes
SIGTRAP = 5

# syscall numbers (x86_64)
SYS_read = 0
SYS_write = 1
SYS_open = 2
SYS_close = 3
SYS_execve = 59
SYS_exit = 60
SYS_connect = 42
SYS_accept = 43
SYS_bind = 49
SYS_listen = 50
SYS_accept4 = 288
SYS_openat = 257
SYS_unlink = 87
SYS_unlinkat = 263
SYS_rename = 82
SYS_renameat = 264
SYS_exit_group = 231
SYS_execveat = 322

class user_regs_struct(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong),
    ]

libc.ptrace.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_long

libc.waitpid.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_int), ctypes.c_int]
libc.waitpid.restype = ctypes.c_int

def _errno() -> int:
    return ctypes.get_errno()

# универсальная “обёртка” над libc.ptrace(...)
# вызывает ptrace(request, pid, addr, data) в ядре через libc
def ptrace(request: int, pid: int, addr: int = 0, data: int = 0) -> int:
    res = libc.ptrace(ctypes.c_ulong(request), ctypes.c_ulong(pid),
                      ctypes.c_void_p(addr), ctypes.c_void_p(data))
    if res == -1:
        err = _errno()
        raise OSError(err, os.strerror(err))
    return int(res)

# ждёт событие от любого трассируемого процесса/потока
def waitpid_any(flags: int) -> Tuple[int, int]:
    status = ctypes.c_int()
    pid = libc.waitpid(-1, ctypes.byref(status), flags | __WALL)
    if pid == -1:
        err = _errno()
        raise OSError(err, os.strerror(err))
    return int(pid), int(status.value)

# ждёт событие от любого трассируемого процесса/потока
def waitpid_pid(pid: int, flags: int) -> Tuple[int, int]:
    status = ctypes.c_int()
    got = libc.waitpid(pid, ctypes.byref(status), flags | __WALL)
    if got == -1:
        err = _errno()
        raise OSError(err, os.strerror(err))
    return int(got), int(status.value)

# проверяет, что процесс остановлен
def WIFSTOPPED(status: int) -> bool:
    return (status & 0xff) == 0x7f

# если процесс остановлен — извлекает номер сигнала, который вызвал остановку
def WSTOPSIG(status: int) -> int:
    return (status >> 8) & 0xff

# проверяет, что процесс завершился нормально
def WIFEXITED(status: int) -> bool:
    return (status & 0x7f) == 0

# если WIFEXITED=True, возвращает код выхода
def WEXITSTATUS(status: int) -> int:
    return (status >> 8) & 0xff

# проверяет, что процесс завершился из-за сигнала
def WIFSIGNALED(status: int) -> bool:
    return ((status & 0x7f) != 0) and ((status & 0x7f) != 0x7f)

# если WIFSIGNALED=True, возвращает каким сигналом убит
def WTERMSIG(status: int) -> int:
    return status & 0x7f

# прикрепляет tracer к процессу: PTRACE_ATTACH
def attach(pid: int) -> None:
    ptrace(PTRACE_ATTACH, pid, 0, 0)

# отцепляет tracer от процесса: PTRACE_DETACH
def detach(pid: int) -> None:
    ptrace(PTRACE_DETACH, pid, 0, 0)

# ставит ключевые опции ptrace через PTRACE_SETOPTIONS
def set_options(pid: int) -> None:
    opts = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT
    ptrace(PTRACE_SETOPTIONS, pid, 0, opts)

# PTRACE_SYSCALL — продолжает процесс, но останавливает его на входе и выходе каждого syscall
def syscall(pid: int, sig: int = 0) -> None:
    ptrace(PTRACE_SYSCALL, pid, 0, sig)

# PTRACE_CONT — просто продолжить выполнение без остановок на syscalls
def cont(pid: int, sig: int = 0) -> None:
    ptrace(PTRACE_CONT, pid, 0, sig)

# получает регистры процесса через PTRACE_GETREGS
def get_regs(pid: int) -> user_regs_struct:
    regs = user_regs_struct()
    ptrace(PTRACE_GETREGS, pid, 0, ctypes.addressof(regs))
    return regs

# читает одно машинное слово из памяти tracee по адресу addr через PTRACE_PEEKDATA
def peek_data(pid: int, addr: int) -> int:
    # returns word (native long)
    res = libc.ptrace(ctypes.c_ulong(PTRACE_PEEKDATA), ctypes.c_ulong(pid),
                      ctypes.c_void_p(addr), None)
    if res == -1 and _errno() != 0:
        err = _errno()
        raise OSError(err, os.strerror(err))
    # On success errno may still be nonzero; ignore.
    return int(res & 0xffffffffffffffff)

# читает n байт из памяти процесса, многократно вызывая peek_data по словам word_size
def read_bytes(pid: int, addr: int, n: int) -> bytes:
    word_size = ctypes.sizeof(ctypes.c_long)
    out = bytearray()
    i = 0
    while i < n:
        w = peek_data(pid, addr + i)
        out.extend(int(w).to_bytes(word_size, byteorder="little", signed=False))
        i += word_size
    return bytes(out[:n])

# читает C-строку (null-terminated) из памяти процесса
def read_cstring(pid: int, addr: int, max_len: int = 4096) -> str:
    if addr == 0:
        return ""
    word_size = ctypes.sizeof(ctypes.c_long)
    out = bytearray()
    i = 0
    while i < max_len:
        w = peek_data(pid, addr + i)
        chunk = int(w).to_bytes(word_size, "little", signed=False)
        if 0 in chunk:
            out.extend(chunk.split(b"\x00", 1)[0])
            break
        out.extend(chunk)
        i += word_size
    return out.decode("utf-8", errors="replace")

# читает из памяти процесса одно машинное слово и трактует его как указатель
def read_ptr(pid: int, addr: int) -> int:
    word_size = ctypes.sizeof(ctypes.c_long)
    data = read_bytes(pid, addr, word_size)
    return int.from_bytes(data, "little", signed=False)

# читает массив аргументов argv процесса
def read_argv(pid: int, argv_ptr: int, max_args: int = 20, max_str: int = 256) -> List[str]:
    args: List[str] = []
    if argv_ptr == 0:
        return args
    word_size = ctypes.sizeof(ctypes.c_long)
    for i in range(max_args):
        p = read_ptr(pid, argv_ptr + i * word_size)
        if p == 0:
            break
        s = read_cstring(pid, p, max_str)
        args.append(s)
    return args

# достает данные из системных вызовов сетевых операций
# используется во время обработки сетевых syscalls (connect, bind, accept/accept4) чтобы из “сырого” аргумента:
# * addr = указатель (число)
# * addrlen = длина
# получить человеко-понятные данные:
# * семейство (AF_INET / AF_INET6)
# * IP
# * порт
def read_sockaddr(pid: int, addr: int, addrlen: int) -> Dict[str, Any]:
    if addr == 0 or addrlen <= 0:
        return {}
    raw = read_bytes(pid, addr, min(addrlen, 128))
    if len(raw) < 2:
        return {}
    family = struct.unpack_from("H", raw, 0)[0]
    if family == socket.AF_INET and len(raw) >= 16:
        # struct sockaddr_in { sa_family_t sin_family; in_port_t sin_port; struct in_addr sin_addr; ... }
        port = struct.unpack_from("!H", raw, 2)[0]
        ip = socket.inet_ntop(socket.AF_INET, raw[4:8])
        return {"family":"AF_INET", "ip": ip, "port": port}
    if family == socket.AF_INET6 and len(raw) >= 28:
        port = struct.unpack_from("!H", raw, 2)[0]
        ip = socket.inet_ntop(socket.AF_INET6, raw[8:24])
        return {"family":"AF_INET6", "ip": ip, "port": port}
    return {"family": int(family)}
