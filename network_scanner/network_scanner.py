from .scan_functions import ScanFunctions
from .password_engines import PasswordEngines
from .reporter import Reporter
from .network_scanner_data.network_vulnerabilities_info import info
import subprocess
import time


class NetworkScanner:
    SSID_HEADER_LEN = 4
    _scan_functions = ScanFunctions()
    _engines = PasswordEngines()
    _reporter = Reporter()

    def print_conclusion(self, conclusion):
        """
        function print the conclusion of the network scanner
        :param conclusion: the conclusion of the scan
        :type conclusion: list
        :return: none
        """
        print("*****************************conclusion*****************************")
        if len(conclusion) == 0:
            print("Please Connect to a Network to Start the Scanning")
        else:
            if conclusion[0]:
                print(info["evil twin"])
            if conclusion[1]:
                print(info["open ssid"])
            if conclusion[2]:
                print(info["common ssid"])
            if conclusion[3] != "No-Username":
                if conclusion[3]:
                    print(info["common router username"])

            if conclusion[4] != "No-Password":
                if conclusion[4]:
                    print(info["common router password"])
            if conclusion[5][0] == -1:
                print("Your password for the network is in the common passwords database, means it will be\n"
                      "cracked instantly, try to change it to more complex and strong password")
            else:
                if conclusion[5][0] != '!':
                    print(conclusion[5][0])
                if conclusion[5][1] != '!':
                    print(conclusion[5][1])
                print("remember good and strong password must contain at least 8 characters, including\n"
                      "numbers, both upper and lower letters, and special symbols like: * or &")

    def _get_ssid(self):
        """
        This function will return the ssid of the connected network
        :return: the ssid of the connected network
        """
        command = "nmcli -t -f active,ssid dev wifi | grep yes"
        ssid = subprocess.run(command, shell=True, stdout=subprocess.PIPE, text=True).stdout
        return [single_ssid[self.SSID_HEADER_LEN:] for single_ssid in ssid.split('\n') if (len(single_ssid) > 1 and single_ssid[0] == 'y')][0]

    def scan(self):
        """
        function scan the network
        """
        ssid = self._get_ssid()
        conclusion = list()

        router_username = input("enter your username for the router, if you don't know, press enter:\n")
        router_password = input("enter your password for the router, if you don't know, press enter:\n")
        self._reporter.start_loading("checking evil twin")
        conclusion.append(self._scan_functions.check_evil_twin(ssid))
        time.sleep(2)
        self._reporter.stop_loading()
        time.sleep(1)
        if ssid != "":
            conclusion.append(ssid != "--")  # need to check if it means the ssid is hidden
            self._reporter.start_loading("checking ssid name")
            conclusion.append(ScanFunctions.find_in_file(ssid, "network_scanner/network_scanner_data/commonssids.txt"))
            time.sleep(2)
            self._reporter.stop_loading()
            time.sleep(1)
            if router_username.lower() != '':
                self._reporter.start_loading("checking router username")
                conclusion.append(ScanFunctions.find_in_file(router_username, "network_scanner/network_scanner_data/users_router.txt"))
                time.sleep(2)
                self._reporter.stop_loading()
                time.sleep(1)
            else:
                conclusion.append("No-Username")
            if router_password.lower() != '':
                self._reporter.start_loading("checking router password")
                conclusion.append(ScanFunctions.find_in_file(router_password, "network_scanner/network_scanner_data/passwords_router.txt"))
                time.sleep(2)
                self._reporter.stop_loading()
                time.sleep(1)
            else:
                conclusion.append("No-Password")
            details = self._scan_functions.get_details(ssid)
            password = details["password"]
            encryption_type = details["encryption_type"]
            self._reporter.start_loading("checking network password")
            conclusion.append(self._engines.password_engines(password))
            time.sleep(2)
            self._reporter.stop_loading()
            time.sleep(1)
        self.print_conclusion(conclusion)



