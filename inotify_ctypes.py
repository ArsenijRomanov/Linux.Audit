# -*- coding: utf-8 -*-

from __future__ import annotations

import ctypes
import ctypes.util
import os
import struct
import threading
from pathlib import Path
from typing import Callable, Dict, Optional, Set, List, Tuple

libc_path = ctypes.util.find_library("c")
if not libc_path:
    raise RuntimeError("libc not found")
libc = ctypes.CDLL(libc_path, use_errno=True)

# inotify flags
IN_NONBLOCK = 0x800
IN_CLOEXEC  = 0x80000

# masks
IN_ACCESS        = 0x00000001
IN_MODIFY        = 0x00000002
IN_ATTRIB        = 0x00000004
IN_CLOSE_WRITE   = 0x00000008
IN_CLOSE_NOWRITE = 0x00000010
IN_OPEN          = 0x00000020
IN_MOVED_FROM    = 0x00000040
IN_MOVED_TO      = 0x00000080
IN_CREATE        = 0x00000100
IN_DELETE        = 0x00000200
IN_DELETE_SELF   = 0x00000400
IN_MOVE_SELF     = 0x00000800
IN_UNMOUNT       = 0x00002000
IN_Q_OVERFLOW    = 0x00004000
IN_IGNORED       = 0x00008000
IN_ISDIR         = 0x40000000

# что подписываемся ловить из (masks)
WATCH_MASK = (
    IN_CREATE | IN_DELETE | IN_MODIFY | IN_MOVED_FROM | IN_MOVED_TO | IN_ATTRIB | IN_CLOSE_WRITE |
    IN_DELETE_SELF | IN_MOVE_SELF
)

libc.inotify_init1.argtypes = [ctypes.c_int]
libc.inotify_init1.restype = ctypes.c_int

libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
libc.inotify_add_watch.restype = ctypes.c_int

libc.inotify_rm_watch.argtypes = [ctypes.c_int, ctypes.c_int]
libc.inotify_rm_watch.restype = ctypes.c_int


class InotifyWatcher:
    def __init__(self, callback: Callable[[str, int, bool], None]):
        """
        callback(full_path, mask, is_dir)
        """
        self._cb = callback                                                 # функция, которая вызывается при событии
        self._fd = libc.inotify_init1(IN_NONBLOCK | IN_CLOEXEC)             # дескриптор, куда приходят все события от ядра
        if self._fd < 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err))
        self._wd_to_path: Dict[int, str] = {}                               # соответствие watch-дескриптора и пути
        self._lock = threading.Lock()                                       # лок
        self._stop = threading.Event()                                      # флаг для остановки _run
        self._thread = threading.Thread(target=self._run, daemon=True)      # запуск функции _run в потоке

    @property
    def fd(self) -> int:
        return int(self._fd)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        try:
            os.close(self._fd)
        except Exception:
            pass

    # добавление подписок
    def add_watch(self, path: str) -> None:
        p = Path(path)
        if not p.exists():
            return
        wd = libc.inotify_add_watch(self._fd, str(p).encode("utf-8"), WATCH_MASK)
        if wd < 0:
            # best effort
            return
        with self._lock:
            self._wd_to_path[int(wd)] = str(p)

    # рекурсивное добавление подписок
    def add_watch_recursive(self, root: str, max_dirs: int = 10_000) -> None:
        p = Path(root)
        if not p.exists():
            return
        count = 0
        # add root first
        self.add_watch(str(p))
        if p.is_dir():
            for dirpath, dirnames, _filenames in os.walk(str(p), followlinks=False):
                self.add_watch(dirpath)
                count += 1
                if count >= max_dirs:
                    break

    # достает пачку данных из fd
    # парсит их
    # при необходимости подписывается на новые директории
    # вызывает callback
    def _run(self) -> None:
        # read buffer (multiple events)
        while not self._stop.is_set():
            try:
                data = os.read(self._fd, 64 * 1024)
                if not data:
                    continue
            except BlockingIOError:
                self._stop.wait(0.2)
                continue
            except OSError:
                break

            off = 0
            while off + 16 <= len(data):
                wd, mask, cookie, name_len = struct.unpack_from("iIII", data, off)
                off += 16
                name = b""
                if name_len:
                    name = data[off:off+name_len].split(b"\x00", 1)[0]
                off += name_len

                with self._lock:
                    base = self._wd_to_path.get(int(wd), "")
                if not base:
                    continue
                full = base
                if name:
                    try:
                        full = str(Path(base) / name.decode("utf-8", errors="replace"))
                    except Exception:
                        full = base
                is_dir = bool(mask & IN_ISDIR)

                # auto-add watch for newly created directories
                if (mask & IN_CREATE) and is_dir:
                    self.add_watch(full)

                try:
                    self._cb(full, int(mask), is_dir)
                except Exception:
                    # keep watcher alive
                    pass
