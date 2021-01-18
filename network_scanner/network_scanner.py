import subprocess
from .scan_functions import ScanFunctions
from .password_engines import PasswordEngines
from .data.network_vulnerabilities_info import info


class NetworkScanner:
    SSID_HEADER_LEN = 4
    _scan_functions = ScanFunctions()
    _engines = PasswordEngines()

    def print_conclusion(self, conclusion):
        """
        This function will print the conclusions of the network scanner
        :param conclusion: the conclusions of the scan
        :type conclusion: list
        """
        print("*****************************Conclusions*****************************")
        if len(conclusion) == 0:
            print("Please Connect to a Network to Start the Scanning")
        else:
            if conclusion[0]:
                print(info["evil twin"])
            else:
                print("No evil twin detected !")
            if conclusion[1]:
                print(info["open ssid"])
            else:
                print("Your network is hidden so it is more secure !")
            if conclusion[2]:
                print(info["common ssid"])
            else:
                print("Your network name is not in the common names of our database\n"
                      " means your network is more safety !")
            if conclusion[3] != "No-Username":
                if conclusion[3]:
                    print(info["common router username"])
                else:
                    print("Your router username is not in the common usernames in our database,\n"
                          "means your network is more safety !")

            if conclusion[4] != "No-Password":
                if conclusion[4]:
                    print(info["common router password"])
                else:
                    print("Your router password is not in the common passwords in our database,\n"
                          "means your network is more safety !")
            if conclusion[5][0] == -1:
                print("Your password for the network is in the common passwords database, means it will be\n"
                      "cracked instantly, try to change it to more complex and strong password")
            else:
                if conclusion[5][0] != '!':
                    print(f"first result of engine calculate estimated time: {conclusion[5][0]}")
                if conclusion[5][1] != '!':
                    print(f"second result of engine calculate estimated time: {conclusion[5][1]}")
                print("remember good and strong password must contain at least 8 characters, including\n"
                      "numbers, both upper and lower letters, and special symbols like: * or &")

    def _get_ssid(self):
        """
        This function will return the ssid of the connected network
        :return: the ssid of the connected network
        :rtype: string
        """
        command = "nmcli -t -f active,ssid dev wifi | grep yes"
        ssid = subprocess.run(command, shell=True, stdout=subprocess.PIPE, text=True).stdout
        return [single_ssid[self.SSID_HEADER_LEN:] for single_ssid in ssid.split('\n') if (len(single_ssid) > 1 and single_ssid[0] == 'y')][0]

    def scan(self):
        """
        This function will run the scan on the connected network
        """
        ssid = self._get_ssid()
        conclusion = list()
        conclusion.append(self._scan_functions.check_evil_twin(ssid))
        if ssid != "":
            conclusion.append(ssid != "--")  # need to check if it means the ssid is hidden
            conclusion.append(ScanFunctions.find_in_file(ssid, "network_scanner/data/commonssids.txt"))
            router_username = input("Enter your router's username. If you don't know it, press n:\n")
            if router_username.lower() != 'n':
                conclusion.append(ScanFunctions.find_in_file(router_username, "network_scanner/data/users_router.txt"))
            else:
                conclusion.append("No-Username")
            router_password = input("Enter your router's password. If you don't know it, press n:\n")
            if router_password.lower() != 'n':
                conclusion.append(ScanFunctions.find_in_file(router_password, "network_scanner/data/passwords_router.txt"))
            else:
                conclusion.append("No-Password")
            details = self._scan_functions.get_details(ssid)
            password = details["password"]
            encryption_type = details["encryption_type"]
            conclusion.append(self._engines.password_engines(password))
        self.print_conclusion(conclusion)
