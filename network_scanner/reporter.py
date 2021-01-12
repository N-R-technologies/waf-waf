import itertools
import threading
import time
import sys


class Reporter:
    _done = False
    _current_thread = None

    def _loading_animation(self, loading_str):
        for sign in itertools.cycle(['|', '/', '-', '\\']):
            if self._done:
                break
            print(f"*{loading_str} {sign}", end="\r")
            time.sleep(0.1)

    def start_loading(self, loading_str):
        self._done = False
        self._current_thread = threading.Thread(target=self._loading_animation, args=(loading_str,))
        self._current_thread.start()

    def stop_loading(self):
        self._done = True

