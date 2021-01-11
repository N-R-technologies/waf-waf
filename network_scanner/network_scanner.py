from network_scanner.scan_functions import ScanFunctions
import subprocess


class EngineError(Exception):
    """class handle error in case one of the engines cant work properly with the given password"""
    def __init__(self, engine_num):
        self._engine_num = engine_num

    def __str__(self):
        return "the engine number: " + str(self._engine_num) + " cant work properly with your password"


class InvalidChar(Exception):
    """class handle error in case the password contain non asci char or symbol or number"""
    def __init__(self, invalid_char):
        self._invalid_char = invalid_char

    def __str__(self):
        return "Your Password contains invalid char: " + self._invalid_char + " so unfortunately we cant analyze it"


class NetworkScanner:
    SSID_HEADER_LEN = 4

    def _get_ssid(self):
        """
        This function will return the ssid of the connected network
        :return: the ssid of the connected network
        """
        command = "nmcli -t -f active,ssid dev wifi | grep yes"
        ssid = subprocess.run(command, shell=True, stdout=subprocess.PIPE, text=True).stdout
        return [single_ssid[self.SSID_HEADER_LEN:] for single_ssid in ssid.split('\n') if (len(single_ssid) > 1 and single_ssid[0] == 'y')][0]

    def scan(self):
        ssid = self._get_ssid()
        conclusion = []
        if check_evil_twin(ssid):
            conclusion.append("there is an access point in your network with the same name!")
        else:
            conclusion.append("no evil twin detected in your wifi network")
        if ssid != "":
            conclusion.append(ssid)
            details = get_details(ssid)
            password = details["password"]
            encryption_type = details["encryption_type"]
            conclusion.append(find_in_file(ssid, "commonssids.txt"))
            conclusion.append(get_estimated_crack_time(password))
            router_username = input("enter your password for the router, if you don't know, press enter")
            if router_username != '\n':
                conclusion.append(find_in_file(router_username, "users_router.txt.txt"))
            else:
                conclusion.append("no_username")
            router_password = input("enter your password for the router, if you don't know, press enter")
            if router_password != '\n':
                conclusion.append(find_in_file(router_password, "passwords_router.txt"))
            else:
                conclusion.append("no_password")
        else:
            conclusion.append("Please Connect to a Network to Start the Scanning")
        print_conclusion(conclusion)

