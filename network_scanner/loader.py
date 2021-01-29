import time
import threading
import itertools
from colors import Colors


class Loader:
    _finish_load = False
    _current_thread = None
    _lock = threading.Lock()

    def _load(self, loading_str, color):
        """
        This function will display the given string with animated loading
        :param loading_str: the string to display on loading
        :param color: the color of the loading
        :type loading_str: string
        :type color: Colors
        """
        with self._lock:
            for sign in itertools.cycle(['|', '/', '-', '\\']):
                if self._finish_load:
                    break
                print(f"* {color}{loading_str} {sign}", end="\r")
                time.sleep(0.15)
            print(f"* {color}{loading_str}  {Colors.GREEN} DONE", end="\r\n")

    def start_loading(self, loading_str, color):
        """
        This function will start the loading as thread
        :param loading_str: the string to display on loading
        :param color: the color of the loading
        :type loading_str: string
        :type color: Colors
        """
        self._finish_load = False
        self._current_thread = threading.Thread(target=self._load, args=(loading_str, color,))
        self._current_thread.start()

    def stop_loading(self):
        """
        This function will tell the loading function to stop
        """
        self._finish_load = True
        time.sleep(0.2)
