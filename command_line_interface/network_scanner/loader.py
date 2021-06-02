import time
import threading
import itertools
from misc import Colors


class Loader:
    _finish_load = False
    _current_thread = None
    _lock = threading.Lock()

    def _load(self, loading_str, color):
        with self._lock:
            for sign in itertools.cycle(['|', '/', '-', '\\']):
                if self._finish_load:
                    break
                print(f"* {color}{loading_str} {sign}", end="\r")
                time.sleep(0.15)
            print(f"* {color}{loading_str}  {Colors.GREEN} DONE", end="\r\n")

    def start_loading(self, loading_str, color):
        self._finish_load = False
        self._current_thread = threading.Thread(target=self._load, args=(loading_str, color,), daemon=True)
        self._current_thread.start()

    def stop_loading(self):
        self._finish_load = True
        time.sleep(0.2)
