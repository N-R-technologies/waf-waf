import subprocess

SSID_HEADER_LEN = 4

def get_ssid():
    '''
    This function will return the ssid of the connected network
    :return: the ssid of the connected network
    '''
    command = "nmcli -t -f active,ssid dev wifi | grep yes"
    ssid = subprocess.run(command, shell=True, stdout=subprocess.PIPE, text=True).stdout
    return ssid[SSID_HEADER_LEN: -1]

def get_details(ssid):
    '''
    This function will return all the details of the connected network
    :param ssid: the ssid of the connected network
    :return: all the details about the connected network from the command "nmcli -t -s connection show <network ssid>"
    '''
    command = "nmcli -t -s connection show " + ssid
    details = subprocess.run(command, shell=True, stdout=subprocess.PIPE, text=True).stdout
    # storing each detail in a dictionary
    details_dict = dict()
    for detail in details.split("\n"):
        key = detail[:detail.find(":")]
        value = detail[detail.find(":") + 1:]
        details_dict[key] = value
    details_dict.popitem() # last item is empty for some reason
    return details_dict

def findInFile(signature, file):
    '''
    This function will check if the given signature appears in the given file
    :param signature: the signature to check if appears in the file
    :param file: the file that contains the common signature type (for example common passwords)
    :return: True if the given signature appears in the given file, otherwise, False
    '''
    signature += '\n'
    with open(file, 'r') as f:
        for line in f:
            if line == signature:
                return True
    return False

def main():
    ssid = get_ssid()
    if ssid != "":
        details = get_details(ssid)
        password = details['802-11-wireless-security.psk']
        print(findInFile(ssid, "commonssids.txt"))
        print(findInFile(password, "passwords.txt"))
    else:
        print("Please Connect to a Network to Start the Scanning")

if __name__ == "__main__":
    main()
