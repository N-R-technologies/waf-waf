import subprocess


class ScanFunctions:
    PASSWORD_HEADER_LEN = 29

    def find_in_file(self, signature, file):
        """
        This function will check if the given signature appears in the given file
        :param signature: the signature to check if appears in the file
        :param file: the file that contains the common signature type (for example common passwords)
        :type signature: string
        :type file: string
        :return: True if the given signature appears in the given file, otherwise, False
        :rtype: boolean
        """
        signature += '\n'
        with open(file, 'r') as f:
            for line in f:
                if line == signature:
                    f.close()
                    return True
            f.close()
        return False

    def get_details(self, ssid):
        """
        This function will return all the details about the connected network
        :param ssid: the ssid of the connected network
        :type ssid: string
        :return: all the details about the connected network
        :rtype: dict
        """
        command = 'nmcli -t -s connection show "' + ssid + '"' + '| grep ^802-11-wireless-security.psk:'
        details = dict()
        details["password"] = subprocess.run(command, shell=True, stdout=subprocess.PIPE, text=True).stdout[self.PASSWORD_HEADER_LEN:]
        command = "nmcli -t -f IN-USE,SECURITY device wifi list | grep '^\*'"
        details["encryption_type"] = subprocess.run(command, shell=True, stdout=subprocess.PIPE, text=True).stdout[2:]
        return details

    def check_evil_twin(self, ssid):
        """
        This function will check if there is another access point in the close
        range of the server which have the same ssid as the user's network
        :param ssid: the ssid of the user's network
        :type ssid: string
        :return: if there is access point with the same ssid
        :rtype: boolean
        """
        command = "nmcli -f SSID device wifi list"
        all_access_points = subprocess.run(command, shell=True, stdout=subprocess.PIPE, text=True).stdout
        return all_access_points.count(ssid + '\n') > 1
