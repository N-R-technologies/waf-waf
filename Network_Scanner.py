import subprocess
from math import pow
from access_points import get_scanner
SSID_HEADER_LEN = 4
PASSWORD_HEADER_LEN = 29


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


def get_ssid():
    """
    This function will return the ssid of the connected network
    :return: the ssid of the connected network
    """
    command = "nmcli -t -f active,ssid dev wifi | grep yes"
    ssid = subprocess.run(command, shell=True, stdout=subprocess.PIPE, text=True).stdout
    return [single_ssid[SSID_HEADER_LEN:] for single_ssid in ssid.split('\n') if (len(single_ssid) > 1 and single_ssid[0] == 'y')][0]


def get_details(ssid):
    """
    This function will return all the details of the connected network
    :param ssid: the ssid of the connected network
    :type ssid: string
    :return: all the details about the connected network from the command "nmcli -t -s connection show <network ssid>"
    """
    command = 'nmcli -t -s connection show "' + ssid + '"'  + '| grep ^802-11-wireless-security.psk:'
    details = dict()
    details["password"] = subprocess.run(command, shell=True, stdout=subprocess.PIPE, text=True).stdout[PASSWORD_HEADER_LEN:]
    command = "nmcli -t -f IN-USE,SECURITY device wifi list | grep '^\*'"
    details["encryption_type"] = subprocess.run(command, shell=True, stdout=subprocess.PIPE, text=True).stdout[2:]
    return details


def convert_to_suitable_format(estimated_time):
    """function convert the estimated time from seconds to more suitable format
    :param estimated_time: the estimated time in seconds
    :type estimated_time: int
    :return type: the new type
    :return estimated_time: the new estimated time (no longer in seconds)
    :rtype type: string
    :rtype estimated_time: int"""
    timeType = ""
    if estimated_time < 60:
        timeType = "seconds"
    elif (estimated_time > 60) and (estimated_time < 60 * 60):
        timeType = "minutes"
        estimated_time = estimated_time / 60
    elif (estimated_time > 60 * 60) and (estimated_time < 60 * 60 * 24):
        timeType = "hours"
        estimated_time = estimated_time / (60 * 60)
    elif (estimated_time > 60 * 60 * 24) and (estimated_time < 60 * 60 * 24 * 30):
        timeType = "days"
        estimated_time = estimated_time / (60 * 60 * 24)
    else:
        timeType = "month"
    return timeType, int(estimated_time)


def print_estimated_time(estimated_time, timeType, engine_num):
    """function print the estimated time it would take to crack your password
    :param estimated_time: the estimated time ot would take to crack your password
    :param timeType: the type of the time (like hours or minutes)
    :param engine_num: the number of the engine which calculated this time
    :type estimated_time: int
    :type timeType: string
    :type engine_num: int
    :return: none"""
    if type != "month":
        print("The engine number " + str(engine_num) + " calculate that it would take about " +
              str(estimated_time) + " " + timeType + " to crack your password")
    else:
        print("The engine number " + str(engine_num) +
              " calculate that it would take more than a month to crack your password")


def analyze_password(password):
    """function analyze password and check its content
    :param password: the password
    :type password: string
    :return have_lower_case: does the password contains lower case letters
    :return have_upper_case: does the password contains upper case letters
    :return have_numbers: does the password contains numbers
    :return have_symbol: does the password contains symbols
    :rtype have_lower_case: boolean
    :rtype have_upper_case: boolean
    :rtype have_numbers: boolean
    :rtype have_symbol: boolean"""
    have_upper_case = False
    have_lower_case = False
    have_numbers = False
    have_symbol = False
    list_symbols = ['@', '_', '!', '#', '$', '%', '^', '&', '*', '(', ')', '<', '>', '?', '/', "\\", '|', '}',
                    '{', '~', ':', ']', '+', '=', '.', '`', ';', "'", '-', '"']
    for char in password:
        if char.isnumeric():
            have_numbers = True
        elif char.islower():
            have_lower_case = True
        elif char.isupper():
            have_upper_case = True
        elif char in list_symbols:
            have_symbol = True
        else:
            raise InvalidChar(char)
    return have_lower_case, have_upper_case, have_numbers, have_symbol


def find_in_file(signature, file):
    """
    This function will check if the given signature appears in the given file
    :param signature: the signature to check if appears in the file
    :param file: the file that contains the common signature type (for example common passwords)
    :type signature: string
    :type file: string
    :return: True if the given signature appears in the given file, otherwise, False
    """
    signature += '\n'
    with open(file, 'r') as f:
        for line in f:
            if line == signature:
                return True
    return False


def get_estimated_crack_time(password):
    """function print the estimated time it would take to crack your password according
    to two separate engines
    :param password: the password
    :type password: string
    :return: none"""
    if find_in_file(password, "passwords.txt"):
        print("Your password will crack instantly because its a common password")
    else:
        try:
            have_lower, have_upper, have_numbers, have_symbol = analyze_password(password)
        except InvalidChar as e:
            print(e.__str__())
        else:
            estimated_time1 = estimate_crack_time_engine1(len(password), have_numbers, have_upper, have_lower, have_symbol)
            timeType, estimated_time1 = convert_to_suitable_format(estimated_time1)
            print_estimated_time(estimated_time1, timeType, 1)
            try:
                estimated_time2 = estimate_crack_time_engine2(len(password), have_numbers, have_upper, have_lower, have_symbol)
            except EngineError as e:
                print(e.__str__())
            else:
                timeType, estimated_time2 = convert_to_suitable_format(estimated_time2)
                print_estimated_time(estimated_time2, timeType, 2)
                print("remember good and strong password must contain at least 8 characters, including"
                      "numbers, bot upper and lower letters, and special symbols like: * or &")


def estimate_crack_time_engine1(password_length, have_numbers, have_upper, have_lower, have_symbols):
    """function calculate with a mathematical formula how long it would take to crack your password with brute force
        :param password_length: the length of the password
        :param have_numbers: does the password contains numbers
        :param have_upper: does the password contains upper case letters
        :param have_lower: does the password contains lower case letters
        :param have_symbols: does the password contains symbols
        :type password_length: integer
        :type have_numbers: boolean
        :type have_upper: boolean
        :type have_lower: boolean
        :type have_symbols: boolean
        :return: the time in seconds it would take to crack your password"""
    KEYS_PER_SECOND = 17042497
    password_type = 0
    if have_lower:
        password_type += 26
    if have_upper:
        password_type += 26
    if have_numbers:
        password_type += 10
    if have_symbols:
        password_type += 30
    combinations = pow(password_type, password_length)
    crack_time_seconds = combinations / KEYS_PER_SECOND
    if crack_time_seconds < 1:
        return 0
    return crack_time_seconds


def estimate_crack_time_engine2(password_length, have_numbers, have_upper, have_lower, have_symbols):
    """function calculate with static table how long it would take to crack your password with brute force attack
    :param password_length: the length of the password
    :param have_numbers: does the password contains numbers
    :param have_upper: does the password contains upper case letters
    :param have_lower: does the password contains lower case letters
    :param have_symbols: does the password contains symbols
    :type password_length: integer
    :type have_numbers: boolean
    :type have_upper: boolean
    :type have_lower: boolean
    :type have_symbols: boolean
    :return: the time in seconds it would take to crack your password
    :rtype: integer"""
    time_crack_table = [[0, 0, 3, 10], [0, 8, 180, 780],
                        [0, 300, 10800, 61200], [4, 345600, -1, -1],
                        [40, -1, -1, -1], [360, -1, -1, -1],
                        [3600, -1, -1, -1], [39600, -1, -1, -1], [345600, -1, -1, -1]]
    time_in_seconds = 0
    if password_length > 14:
        time_in_seconds = 1000000
    elif password_length < 5:
        time_in_seconds = 0
    else:
        if have_numbers and have_upper and have_lower and have_symbols:
            password_strength = 3
        elif have_numbers and have_upper and have_lower:
            password_strength = 2
        elif have_upper and have_lower and not have_symbols:
            password_strength = 1
        elif have_numbers and not (have_upper or have_lower or have_symbols):
            password_strength = 0
        else:
            raise EngineError(2)
        time_in_seconds = time_crack_table[password_length - 5][password_strength]
        if time_in_seconds == -1:
            time_in_seconds = 1000000
    return time_in_seconds


def check_evil_twin(ssid):
    """function check if there is another access point in the close range of the server
    which have the same ssid as the user's network
    :param all_access_points: all the access point in close range
    :param ssid: the ssid of the user's network
    :type ssid: string
    :return: if there is access point with the same ssid
    :rtype: boolean
    """
    command = "nmcli -f SSID device wifi list"
    all_access_points = subprocess.run(command, shell=True, stdout=subprocess.PIPE, text=True).stdout
    return all_access_points.count(ssid + '\n') > 1


def main():
    ssid = get_ssid()
    if check_evil_twin(ssid):
        print("there is an access point in your network with the same name!")
    else:
        print("no evil twin detected in your wifi network")
    if ssid != "":
        details = get_details(ssid)
        check_evil_twin(ssid)
        password = details["password"]
        encryption_type = details["encryption_type"]
        print(find_in_file(ssid, "commonssids.txt"))
        get_estimated_crack_time()
        router_username = input("enter your password for the router, if you don't know, press enter")
        if router_username != '\n':
            print(find_in_file(router_username, "users_router.txt.txt"))
        router_password = input("enter your password for the router, if you don't know, press enter")
        if router_password != '\n':
            print(find_in_file(router_password, "passwords_router.txt"))
    else:
        print("Please Connect to a Network to Start the Scanning")


if __name__ == "__main__":
    main()
