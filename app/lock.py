# -*- coding: utf-8 -*-
"""
进程级文件锁：CLI（antipole 命令）与主服务共用同一把，避免同时改同一批内核状态。
  - 主服务端用 shared：多个服务任务可并发（SH 与 SH 互不冲突），只在各自改动瞬间持锁
  - CLI 端用 exclusive：整条命令独占，待服务端当前操作完成后执行
同任务内可重入（contextvars 按 asyncio 任务隔离），嵌套时只升级、不重复加锁，
避免 flock 同进程不同 fd 自锁；并发的 asyncio 任务各自持有自己的 fd，语义正确。
非 Linux（开发机）降级为无操作。
"""
import contextlib
import contextvars
import os
import time
from pathlib import Path

try:
    import fcntl
    _LOCK_SH = fcntl.LOCK_SH
    _LOCK_EX = fcntl.LOCK_EX
except ImportError:      # Windows/开发机
    fcntl = None
    _LOCK_SH, _LOCK_EX = 1, 2

# 每个 asyncio 任务（contextvar 副本）一份锁栈 [(fd, mode)]，模式只升不降
_stack = contextvars.ContextVar("antipole_mutex_stack", default=None)


class Mutex:
    def __init__(self, path: str, timeout: float = 60.0):
        self.path = Path(path)
        self.timeout = timeout

    def _open(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        return os.open(str(self.path), os.O_CREAT | os.O_RDWR, 0o600)

    def _lock(self, fd: int, mode: int):
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                fcntl.flock(fd, mode | fcntl.LOCK_NB)
                return
            except OSError:
                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        f"等锁超时: {self.path} (模式 "
                        f"{'SH' if mode == _LOCK_SH else 'EX'})")
                time.sleep(0.05)

    @contextlib.contextmanager
    def shared(self):
        with self._acquire(_LOCK_SH):
            yield

    @contextlib.contextmanager
    def exclusive(self):
        with self._acquire(_LOCK_EX):
            yield

    @contextlib.contextmanager
    def _acquire(self, mode: int):
        if fcntl is None:
            yield
            return
        st = _stack.get()
        created = st is None
        if created:
            st = []
            _stack.set(st)
        if not st or mode > st[-1][1]:
            fd = self._open()
            self._lock(fd, mode)
            st.append((fd, mode))
        try:
            yield
        finally:
            if st and st[-1][1] == mode:
                fd, _ = st.pop()
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                finally:
                    os.close(fd)
            if created and not st:
                _stack.set(None)
