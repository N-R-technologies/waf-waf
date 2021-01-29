import os
import subprocess


class ScanFunctions:
    RECOMMENDED_ENCRYPTION_TYPE = "wpa2"

    def get_ssid(self):
        """
        This function will return the ssid of the connected network
        :return: the ssid of the connected network
        :rtype: string or None
        """
        command = "nmcli -t -f active,ssid dev wifi | grep -oP '(?<=^yes:).*'"
        ssid = subprocess.run(command, shell=True, stdout=subprocess.PIPE, text=True).stdout[:-1]
        if ssid == "":
            return None
        return ssid

    def check_evil_twin(self, ssid):
        """
        This function will check if there is an evil twin - another access point
        in the close range of the server which have the same ssid as the user's network
        :param ssid: the ssid of the user's network
        :type ssid: string
        :return: True, if there is an evil twin, otherwise, False
        :rtype: boolean
        """
        command = "nmcli -f SSID device wifi list"
        all_access_points = subprocess.run(command, shell=True, stdout=subprocess.PIPE, text=True).stdout
        access_points_list = all_access_points.split('\n')
        access_points_list = list(map(str.strip, access_points_list))
        ssid = ssid.strip()
        return access_points_list.count(ssid) > 1

    def find_in_file(self, signature, file):
        """
        This function will check if the given signature appears in the given file
        :param signature: the signature to check if it appears in the file
        :param file: the file that contains the common signature type
        :type signature: string
        :type file: string
        :return: True, if the given signature appears in the given file, otherwise, False
        :rtype: boolean
        """
        if os.path.exists(file):
            signature += '\n'
            with open(file, 'r') as f:
                for line in f:
                    if line == signature:
                        f.close()
                        return True
                f.close()
            return False
        else:
            raise FileNotFoundError

    def get_network_details(self, ssid):
        """
        This function will return all the details about the connected network
        :param ssid: the ssid of the connected network
        :type ssid: string
        :return: all the details about the connected network
        :rtype: dict
        """
        command = "nmcli -t -s connection show '" + ssid + "' | grep -oP '(?<=^802-11-wireless-security.psk:).*'"
        details = dict()
        details["password"] = subprocess.run(command, shell=True, stdout=subprocess.PIPE, text=True).stdout[:-1]
        command = "nmcli -t -f IN-USE,SECURITY device wifi list | grep -oP '(?<=^\*:).*'"
        details["encryption_type"] = subprocess.run(command, shell=True, stdout=subprocess.PIPE, text=True).stdout[:-1]
        return details

    def check_encryption_type(self, encryption_type):
        """
        This function will check if the encryption type
        is WPA2, the recommended and safer one
        :param encryption_type: the network's encryption type
        :type encryption_type: string
        :return: True, if the encryption type is not WPA2, otherwise, False
        :rtype: boolean
        """
        return self.RECOMMENDED_ENCRYPTION_TYPE not in encryption_type.lower()
