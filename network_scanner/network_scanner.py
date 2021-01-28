from .scan_functions import ScanFunctions
from .password_engines import PasswordEngines
from .runner import Runner
from .reporter import Reporter
from colors import Colors


class NetworkScanner:
    COMMON_SSIDS = "network_scanner/data/files/common_ssids.txt"
    COMMON_ROUTER_USERNAMES = "network_scanner/data/files/router_usernames.txt"
    COMMON_ROUTER_PASSWORDS = "network_scanner/data/files/router_passwords.txt"

    _scan_functions = ScanFunctions()
    _engines = PasswordEngines()
    _runner = Runner()
    _reporter = Reporter()

    def scan(self, router_username, router_password):
        """
        This function will scan the network
        :param router_username: the username of the router
        :param router_password: the password of the router
        :type router_username: string
        :type router_password: string
        """
        ssid = self._runner.execute_operation("Receiving network's SSID", Colors.BLUE, self._scan_functions.get_ssid)
        if ssid is not None:
            results = dict()
            results["evil twin"] = self._runner.execute_operation("Checking Evil Twin", Colors.WHITE, self._scan_functions.check_evil_twin, ssid)
            if ssid != "":
                find_in_file = self._scan_functions.find_in_file
                results.append(ssid != "--")
                results.append(self._runner.execute_operation("Checking router's SSID", Colors.BEIGE, find_in_file, ssid, self.COMMON_SSIDS))
                results["open ssid"] = (ssid != "--", Colors.BEIGE)
                results["common ssid"] = (self._scan_functions.find_in_file(ssid, self.COMMON_SSIDS), Colors.BEIGE)
                if router_username != "":
                    results["common router username"] = (self._scan_functions.find_in_file(router_username, self.COMMON_ROUTER_USERNAMES), Colors.PURPLE)
                    results.append(self._runner.execute_operation("Checking router's username", Colors.PURPLE, find_in_file, router_username, self.COMMON_ROUTER_USERNAMES))
                if router_password != "":
                    results["common router password"] = (self._scan_functions.find_in_file(router_password, self.COMMON_ROUTER_PASSWORDS), Colors.CYAN)
                details = self._scan_functions.get_network_details(ssid)
                    results.append(self._runner.execute_operation("Checking router's password", Colors.CYAN, find_in_file, router_password, self.COMMON_ROUTER_PASSWORDS))
                details = self._scan_functions.get_details(ssid)
                password = details["password"]
                self._engines.password_engines(password)
                results["password estimated crack time"] = (True, Colors.ORANGE)
                time.sleep(2)
                self._loader.stop_loading()
                time.sleep(1)
                results.append(self._runner.execute_operation("Checking network's password", Colors.ORANGE, self._engines.password_engines, password))
                encryption_type = details["encryption_type"]
                self._loader.start_loading("Checking network's encryption", Colors.PINK)
                results["broken encryption type"] = (self._scan_functions.check_encryption_type(encryption_type), Colors.PINK)
                time.sleep(2)
                self._loader.stop_loading()
                time.sleep(1)

                results.append(self._runner.execute_operation("Checking network's encryption", Colors.PINK, self._scan_functions.check_encryption_type, encryption_type))

            self._reporter.report_conclusions(results)
        else:
            print("Please connect to a network to start the scan")
