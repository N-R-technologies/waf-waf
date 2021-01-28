import time
import subprocess
from .scan_functions import ScanFunctions
from .password_engines import PasswordEngines
from .reporter import Reporter
from .loader import Loader
from colors import Colors


class NetworkScanner:
    COMMON_SSIDS = "network_scanner/data/files/common_ssids.txt"
    COMMON_ROUTER_USERNAMES = "network_scanner/data/files/router_usernames.txt"
    COMMON_ROUTER_PASSWORDS = "network_scanner/data/files/router_passwords.txt"

    _scan_functions = ScanFunctions()
    _engines = PasswordEngines()
    _reporter = Reporter()
    _loader = Loader()

    def scan(self, router_username, router_password):
        """
        This function will scan the network
        :param router_username: the username of the router
        :param router_password: the password of the router
        :type router_username: string
        :type router_password: string
        """
        print("Starting the scan...")
        ssid = self._scan_functions.get_ssid()
        if ssid is not None:
            results = list()

            self._loader.start_loading("Checking Evil Twin", Colors.WHITE)
            results.append(self._scan_functions.check_evil_twin(ssid))
            time.sleep(2)
            self._loader.stop_loading()
            time.sleep(1)
            if ssid != "":
                results.append(ssid != "--")  # need to check if it means the ssid is hidden
                self._loader.start_loading("Checking router's SSID", Colors.RED)
                results.append(self._scan_functions.find_in_file(ssid, self.COMMON_SSIDS))
                time.sleep(2)
                self._loader.stop_loading()
                time.sleep(1)
                if router_username != "":
                    self._loader.start_loading("Checking router's username", Colors.PURPLE)
                    results.append(self._scan_functions.find_in_file(router_username, self.COMMON_ROUTER_USERNAMES))
                    time.sleep(2)
                    self._loader.stop_loading()
                    time.sleep(1)
                else:
                    results.append("No-Username")
                if router_password != "":
                    self._loader.start_loading("Checking router's password", Colors.CYAN)
                    results.append(self._scan_functions.find_in_file(router_password, self.COMMON_ROUTER_PASSWORDS))
                    time.sleep(2)
                    self._loader.stop_loading()
                    time.sleep(1)
                else:
                    results.append("No-Password")
                details = self._scan_functions.get_network_details(ssid)
                password = details["password"]
                self._loader.start_loading("Checking network's password")
                results.append(self._engines.password_engines(password))
                time.sleep(2)
                self._loader.stop_loading()
                time.sleep(1)
                encryption_type = details["encryption_type"]
                self._loader.start_loading("Checking network's encryption")
                results.append(self._scan_functions.check_encryption_type(encryption_type))
                time.sleep(2)
                self._loader.stop_loading()
                time.sleep(1)
            self._reporter.report_conclusions(results)
            self._reporter.report_log()
            self._reporter.reset_conclusions()
        else:
            print("Please connect to a network to start the scan")
