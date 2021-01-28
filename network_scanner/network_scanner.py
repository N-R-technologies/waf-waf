from .scan_functions import ScanFunctions
from .password_engines import PasswordEngines
from .runner import Runner
from .reporter import Reporter
from colors import Colors


class NetworkScanner:
    COMMON_SSIDS = "network_scanner/data/files/common_ssids.txt"
    COMMON_ROUTER_USERNAMES = "network_scanner/data/files/router_usernames.txt"
    COMMON_ROUTER_PASSWORDS = "network_scanner/data/files/router_passwords.txt"
    SSID_HEADER_LEN = 4

    _scan_functions = ScanFunctions()
    _engines = PasswordEngines()
    _runner = Runner()
    _reporter = Reporter()

    def _get_ssid(self):
        """
        This function will return the ssid of the connected network
        :return: the ssid of the connected network
        :rtype: string or None
        """
        command = "nmcli -t -f active,ssid dev wifi | grep yes:"
        ssid = subprocess.run(command, shell=True, stdout=subprocess.PIPE, text=True).stdout
        if ssid == "":
            return None
        return [single_ssid[self.SSID_HEADER_LEN:] for single_ssid in ssid.split('\n') if
                (len(single_ssid) > 1 and single_ssid[0:self.SSID_HEADER_LEN] == "yes:")][0]

    def scan(self, router_username, router_password):
        """
        This function will scan the network
        :param router_username: the username of the router
        :param router_password: the password of the router
        :type router_username: string
        :type router_password: string
        """
        ssid = self._runner.execute_operation("Receiving network's SSID", Colors.BLUE, self._get_ssid)
        if ssid is not None:
            results = list()

            results.append(self._runner.execute_operation("Checking Evil Twin", Colors.WHITE, self._scan_functions.check_evil_twin, ssid))
            if ssid != "":
                find_in_file = self._scan_functions.find_in_file
                results.append(ssid != "--")
                results.append(self._runner.execute_operation("Checking router's SSID", Colors.BEIGE, find_in_file, ssid, self.COMMON_SSIDS))
                if router_username != "":
                    results.append(self._runner.execute_operation("Checking router's username", Colors.PURPLE, find_in_file, router_username, self.COMMON_ROUTER_USERNAMES))
                if router_password != "":
                    results.append(self._runner.execute_operation("Checking router's password", Colors.CYAN, find_in_file, router_password, self.COMMON_ROUTER_PASSWORDS))
                details = self._scan_functions.get_details(ssid)
                password = details["password"]
                results.append(self._runner.execute_operation("Checking network's password", Colors.ORANGE, self._engines.password_engines, password))
                encryption_type = details["encryption_type"]
                results.append(self._runner.execute_operation("Checking network's encryption", Colors.PINK, self._scan_functions.check_encryption_type, encryption_type))

            self._reporter.report_conclusions(results)
            self._reporter.report_log()
            self._reporter.reset_conclusions()
        else:
            print("Please connect to a network to start the scan")
