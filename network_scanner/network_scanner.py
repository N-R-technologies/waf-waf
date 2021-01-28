import time
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
            results = dict()

            self._loader.start_loading("Checking Evil Twin", Colors.WHITE)
            results["evil twin"] = (self._scan_functions.check_evil_twin(ssid), Colors.WHITE)
            time.sleep(2)
            self._loader.stop_loading()
            time.sleep(1)
            if ssid != "":
                results["open ssid"] = (ssid != "--", Colors.BEIGE)
                self._loader.start_loading("Checking router's SSID", Colors.BEIGE)
                results["common ssid"] = (self._scan_functions.find_in_file(ssid, self.COMMON_SSIDS), Colors.BEIGE)
                time.sleep(2)
                self._loader.stop_loading()
                time.sleep(1)
                if router_username != "":
                    self._loader.start_loading("Checking router's username", Colors.PURPLE)
                    results["common router username"] = (self._scan_functions.find_in_file(router_username, self.COMMON_ROUTER_USERNAMES), Colors.PURPLE)
                    time.sleep(2)
                    self._loader.stop_loading()
                    time.sleep(1)
                if router_password != "":
                    self._loader.start_loading("Checking router's password", Colors.CYAN)
                    results["common router password"] = (self._scan_functions.find_in_file(router_password, self.COMMON_ROUTER_PASSWORDS), Colors.CYAN)
                    time.sleep(2)
                    self._loader.stop_loading()
                    time.sleep(1)
                details = self._scan_functions.get_network_details(ssid)
                password = details["password"]
                self._loader.start_loading("Checking network's password", Colors.ORANGE)
                self._engines.password_engines(password)
                results["password estimated crack time"] = (True, Colors.ORANGE)
                time.sleep(2)
                self._loader.stop_loading()
                time.sleep(1)
                encryption_type = details["encryption_type"]
                self._loader.start_loading("Checking network's encryption", Colors.PINK)
                results["broken encryption type"] = (self._scan_functions.check_encryption_type(encryption_type), Colors.PINK)
                time.sleep(2)
                self._loader.stop_loading()
                time.sleep(1)

            self._reporter.report_conclusions(results)
        else:
            print("Please connect to a network to start the scan")
