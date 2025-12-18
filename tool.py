import os
import sys
import time
import hashlib
import psutil

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

MONITOR_PATHS = [
    r"C:\monitor",
]

TIME_WINDOW = 5
FILE_CHANGE_THRESHOLD = 10
RENAME_THRESHOLD = 10

CANARY_FILES = [
    r"C:\monitor\canary1.txt",
    r"C:\monitor\canary2.txt",
]

SYSTEM_PROCESSES = [
    "svchost.exe", "lsass.exe", "wininit.exe", "csrss.exe",
    "services.exe", "smss.exe", "explorer.exe",
    "System", "Registry",
    "MsMpEng.exe", "SecurityHealthService.exe", "smartscreen.exe",
]


class RansomwareEngine:
    def __init__(self, log_callback):
        self.log = log_callback
        self.observer = None
        self.running = False
        self.canary_hashes = {}

    # ---------- Canary setup ----------
    def setup_canaries(self):
        self.canary_hashes = {}
        for path in CANARY_FILES:
            # ensure directory exists
            parent = os.path.dirname(path)
            if parent and not os.path.exists(parent):
                os.makedirs(parent, exist_ok=True)

            if not os.path.exists(path):
                with open(path, "w", encoding="utf-8") as f:
                    f.write("CANARY FILE — DO NOT MODIFY")
                os.system(f'attrib +h "{path}"')
                self.log(f"[CANARY] Created: {path}")

            with open(path, "rb") as f:
                self.canary_hashes[path] = hashlib.sha256(f.read()).hexdigest()

    # ---------- Start / Stop ----------
    def start(self):
        if self.running:
            return

        self.running = True

        try:
            self.setup_canaries()
            handler = self._create_handler()

            self.observer = Observer()

            scheduled_any = False
            for path in MONITOR_PATHS:
                if os.path.exists(path):
                    self.observer.schedule(handler, path, recursive=True)
                    self.log(f"[MONITOR] {path}")
                    scheduled_any = True
                else:
                    self.log(f"[WARN] Path not found: {path}")

            if not scheduled_any:
                self.log("[WARN] No valid paths to monitor; stopping.")
                self.running = False
                return

            # This can fail on some Python 3.13 + watchdog combinations on Windows
            self.observer.start()
            self.log("[STATUS] Monitoring started")

        except Exception as e:
            self.log(f"[ERROR] Failed to start observer: {e}")
            self.running = False
            # if observer partially created, try to stop safely
            try:
                if self.observer is not None:
                    self.observer.stop()
            except Exception:
                pass

    def stop(self):
        if not self.running:
            # still try to cleanup if observer exists but engine marked stopped
            if self.observer is None:
                return

        self.running = False

        if self.observer is None:
            self.log("[STATUS] Monitoring stopped")
            return

        # IMPORTANT: avoid join() when observer thread was never started
        try:
            alive = False
            try:
                alive = self.observer.is_alive()
            except Exception:
                alive = False

            # stopping is safe even if not alive (usually), but join is not
            try:
                self.observer.stop()
            except Exception:
                pass

            if alive:
                try:
                    self.observer.join(timeout=3)
                except Exception:
                    pass

        finally:
            self.observer = None
            self.log("[STATUS] Monitoring stopped")

    # ---------- Detection ----------
    def _create_handler(self):
        engine = self

        class Handler(FileSystemEventHandler):
            def __init__(self):
                self.mod_count = 0
                self.rename_count = 0
                self.start_time = time.time()

            def on_modified(self, event):
                if event.is_directory:
                    return
                engine.log(f"[MODIFIED] {event.src_path}")
                self.mod_count += 1
                self._check(event.src_path)

            def on_moved(self, event):
                if event.is_directory:
                    return
                engine.log(f"[RENAMED] {event.src_path} → {event.dest_path}")
                self.rename_count += 1
                self._check(None)

            def _check(self, path):
                if time.time() - self.start_time > TIME_WINDOW:
                    self.mod_count = 0
                    self.rename_count = 0
                    self.start_time = time.time()

                if self.mod_count >= FILE_CHANGE_THRESHOLD:
                    engine._alert("High file modification rate")

                if self.rename_count >= RENAME_THRESHOLD:
                    engine._alert("Mass file renaming")

                if path in engine.canary_hashes:
                    try:
                        with open(path, "rb") as f:
                            h = hashlib.sha256(f.read()).hexdigest()
                        if h != engine.canary_hashes[path]:
                            engine._alert("Canary file modified")
                    except Exception as e:
                        engine.log(f"[WARN] Canary read failed: {e}")

        return Handler()

    # ---------- Mitigation ----------
    def _alert(self, reason):
        self.log(f"[ALERT] {reason}")
        self._kill_process()

    def _kill_process(self):
        self.log("[ACTION] Selecting recent user process")
        candidates = []
        current_pid = os.getpid()

        for proc in psutil.process_iter(['pid', 'name', 'create_time', 'cmdline']):
            try:
                # Never kill the GUI process itself
                if proc.info['pid'] == current_pid:
                    continue

                if proc.info['name'] in SYSTEM_PROCESSES:
                    continue

                # Skip GUI process (check cmdline for gui scripts)
                cmdline = proc.info.get('cmdline') or []
                cmdline_str = ' '.join(cmdline).lower()
                if 'gui_qt.py' in cmdline_str or 'gui.py' in cmdline_str:
                    continue

                age = time.time() - proc.info['create_time']
                if age < 180:
                    candidates.append((proc.pid, proc.info['name'], age))
            except Exception:
                continue

        if not candidates:
            self.log("[ACTION] No process killed")
            return

        pid, name, _ = sorted(candidates, key=lambda x: x[2])[0]
        os.system(f"taskkill /F /PID {pid}")
        self.log(f"[ACTION] Killed {name} (PID {pid})")
