from .scan_functions import ScanFunctions
from .password_engines import PasswordEngines
from .runner import Runner
from .reporter import Reporter
from misc import Colors


class NetworkScanner:
    COMMON_SSIDS = "command_line_interface/network_scanner/data/files/common_ssids.txt"
    COMMON_ROUTER_USERNAMES = "command_line_interface/network_scanner/data/files/router_usernames.txt"
    COMMON_ROUTER_PASSWORDS = "command_line_interface/network_scanner/data/files/router_passwords.txt"

    _scan_functions = ScanFunctions()
    _engines = PasswordEngines()
    _runner = Runner()
    _reporter = Reporter()

    def scan(self, router_username, router_password):
        ssid = self._runner.execute_operation("Receiving network's SSID", Colors.BLUE, self._scan_functions.get_ssid)
        if ssid is not None:
            results = dict()
            results["Evil Twin"] = (self._runner.execute_operation("Checking Evil Twin", Colors.WHITE, self._scan_functions.check_evil_twin, ssid), Colors.WHITE)
            find_in_file = self._scan_functions.find_in_file
            results["Open SSID"] = (ssid != "--", Colors.BEIGE)
            results["Router SSID"] = (self._runner.execute_operation("Checking router's SSID", Colors.BEIGE, find_in_file, ssid, self.COMMON_SSIDS), Colors.BEIGE)
            if router_username != "":
                results["Router Username"] = (self._runner.execute_operation("Checking router's username", Colors.PURPLE, find_in_file, router_username, self.COMMON_ROUTER_USERNAMES), Colors.PURPLE)
            if router_password != "":
                results["Router Password"] = (self._runner.execute_operation("Checking router's password", Colors.CYAN, find_in_file, router_password, self.COMMON_ROUTER_PASSWORDS), Colors.CYAN)
            network_details = self._scan_functions.get_network_details(ssid)
            password = network_details["password"]
            self._runner.execute_operation("Checking network's password", Colors.ORANGE, self._engines.password_engines, password)
            results["Password Estimated Crack Time"] = (True, Colors.ORANGE)
            results["Good Password Recommendation"] = (True, Colors.ORANGE)
            encryption_type = network_details["encryption_type"]
            results["Broken Encryption Type"] = (self._runner.execute_operation("Checking network's encryption", Colors.PINK, self._scan_functions.check_encryption_type, encryption_type), Colors.PINK)

            self._reporter.report_conclusions(results)
        else:
            print(f"{Colors.BLUE}\nPlease connect to a network to start the scan")
