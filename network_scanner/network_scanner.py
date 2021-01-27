from .scan_functions import ScanFunctions
from .password_engines import PasswordEngines
from .reporter import Reporter
from .runner import Runner
from colors import Colors


class NetworkScanner:
    COMMON_SSIDS = "network_scanner/data/files/common_ssids.txt"
    COMMON_ROUTER_USERNAMES = "network_scanner/data/files/router_usernames.txt"
    COMMON_ROUTER_PASSWORDS = "network_scanner/data/files/router_passwords.txt"

    _scan_functions = ScanFunctions()
    _engines = PasswordEngines()
    _reporter = Reporter()
    _runner = Runner()

    def scan(self, router_username, router_password):
        """
        This function will scan the network
        :param router_username: the username of the router
        :param router_password: the password of the router
        :type router_username: string
        :type router_password: string
        """
        ssid = self._runner.execute_operation("Receiving your SSID", Colors.BLUE, self._scan_functions.get_ssid)
        if ssid is not None:
            results = dict()

            results["evil twin"] = [self._runner.execute_operation("Checking Evil Twin", Colors.WHITE, self._scan_functions.check_evil_twin, ssid), Colors.WHITE]
            if ssid != "":
                find_in_file = self._scan_functions.find_in_file
                results["open ssid"] = [ssid != "--", Colors.BEIGE]
                results["common ssid"] = [self._runner.execute_operation("Checking router's SSID", Colors.BEIGE, find_in_file, ssid, self.COMMON_SSIDS), Colors.BEIGE]
                if router_username != "":
                    results["common router username"] = [self._runner.execute_operation("Checking router's username", Colors.PURPLE, find_in_file, router_username, self.COMMON_ROUTER_USERNAMES), Colors.PURPLE]
                if router_password != "":
                    results["common router password"] = [self._runner.execute_operation("Checking router's password", Colors.CYAN, find_in_file, router_password, self.COMMON_ROUTER_PASSWORDS), Colors.CYAN]
                details = self._scan_functions.get_network_details(ssid)
                password = details["password"]
                results["password estimated crack time"] = [self._runner.execute_operation("Checking network's password", Colors.ORANGE, self._engines.password_engines, password), Colors.ORANGE]
                encryption_type = details["encryption_type"]
                results["broken encryption type"] = [self._runner.execute_operation("Checking network's encryption", Colors.PINK, self._scan_functions.check_encryption_type, encryption_type), Colors.PINK]
            self._reporter.report_conclusions(results)
        else:
            print("Please connect to a network to start the scan")
