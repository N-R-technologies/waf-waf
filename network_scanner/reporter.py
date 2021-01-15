import itertools
import threading
import time


class Reporter:
    _done = False
    _current_thread = None

    def _loading_animation(self, loading_str):
        for sign in itertools.cycle(['|', '/', '-', '\\']):
            if self._done:
                break
            print(f"*{loading_str} {sign}", end="\r")
            time.sleep(0.1)
        print(f"*{loading_str}  \033[92m DONE", end="\r")
        print('\033[94m')

    def start_loading(self, loading_str):
        self._done = False
        self._current_thread = threading.Thread(target=self._loading_animation, args=(loading_str,))
        self._current_thread.start()

    def stop_loading(self):

        self._done = True

