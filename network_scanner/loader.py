import time
import threading
import itertools


class Loader:
    _finish_load = False
    _current_thread = None

    def _load(self, loading_str):
        """
        This function will display the given string with animated loading
        :param loading_str: the string to display on loading
        :type loading_str: string
        """
        for sign in itertools.cycle(['|', '/', '-', '\\']):
            if self._finish_load:
                break
            print(f"* {loading_str} {sign}", end="\r")
            time.sleep(0.1)
        print(f"* {loading_str}  \033[92m DONE", end="\r")
        print('\033[94m')

    def start_loading(self, loading_str):
        """
        This function will start the loading as thread
        :param loading_str: the string to display on loading
        :type loading_str: string
        """
        self._finish_load = False
        self._current_thread = threading.Thread(target=self._load, args=(loading_str,))
        self._current_thread.start()

    def stop_loading(self):
        """
        This function will tell the loading function to stop
        """
        self._finish_load = True
