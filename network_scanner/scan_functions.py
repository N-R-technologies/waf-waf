import subprocess
PASSWORD_HEADER_LEN = 29


class ScanFunctions:

    def get_details(self,ssid):
        """
        This function will return all the details of the connected network
        :param ssid: the ssid of the connected network
        :type ssid: string
        :return: all the details about the connected network from the command "nmcli -t -s connection show <network ssid>"
        """
        command = 'nmcli -t -s connection show "' + ssid + '"' + '| grep ^802-11-wireless-security.psk:'
        details = dict()
        details["password"] = subprocess.run(command, shell=True, stdout=subprocess.PIPE, text=True).stdout[PASSWORD_HEADER_LEN:]
        command = "nmcli -t -f IN-USE,SECURITY device wifi list | grep '^\*'"
        details["encryption_type"] = subprocess.run(command, shell=True, stdout=subprocess.PIPE, text=True).stdout[2:]
        return details

    def convert_to_suitable_format(self, estimated_time):
        """function convert the estimated time from seconds to more suitable format
        :param estimated_time: the estimated time in seconds
        :type estimated_time: int
        :return type: the new type
        :return estimated_time: the new estimated time (no longer in seconds)
        :rtype type: string
        :rtype estimated_time: int"""
        time_type = ""
        if estimated_time < 60:
            time_type = "seconds"
        elif (estimated_time > 60) and (estimated_time < 60 * 60):
            time_type = "minutes"
            estimated_time = estimated_time / 60
        elif (estimated_time > 60 * 60) and (estimated_time < 60 * 60 * 24):
            time_type = "hours"
            estimated_time = estimated_time / (60 * 60)
        elif (estimated_time > 60 * 60 * 24) and (estimated_time < 60 * 60 * 24 * 30):
            time_type = "days"
            estimated_time = estimated_time / (60 * 60 * 24)
        else:
            timeType = "month"
        return timeType, int(estimated_time)

    def get_estimated_time(self, estimated_time, time_type, engine_num):
        """function print the estimated time it would take to crack your password
        :param estimated_time: the estimated time ot would take to crack your password
        :param time_type: the type of the time (like hours or minutes)
        :param engine_num: the number of the engine which calculated this time
        :type estimated_time: int
        :type time_type: string
        :type engine_num: int
        :return: the estimated crack time
        :rtype: string"""
        if type != "month":
            return("The engine number " + str(engine_num) + " calculate that it would take about " +
                   str(estimated_time) + " " + time_type + " to crack your password")
        return("The engine number " + str(engine_num) +
               " calculate that it would take more than a month to crack your password")

    def analyze_password(self, password):
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

    def find_in_file(self, signature, file):
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

    def get_estimated_crack_time(self, password):
        """function print the estimated time it would take to crack your password according
        to two separate engines
        :param password: the password
        :type password: string
        :return: the estimated crack time
        :rtype: string"""
        if find_in_file(password, "passwords.txt"):
            print("Your password will crack instantly because its a common password")
        else:
            try:
                have_lower, have_upper, have_numbers, have_symbol = analyze_password(password)
            except InvalidChar as e:
                print(e.__str__())
                return e.__str__()
            else:
                estimated_time1 = estimate_crack_time_engine1(len(password), have_numbers, have_upper, have_lower, have_symbol)
                time_type, estimated_time1 = convert_to_suitable_format(estimated_time1)
                crack_time1 = get_estimated_time(estimated_time1, time_type, 1)
                try:
                    estimated_time2 = estimate_crack_time_engine2(len(password), have_numbers, have_upper, have_lower, have_symbol)
                except EngineError as e:
                    print(e.__str__())
                    return crack_time1, e.__str__()
                else:
                    time_type, estimated_time2 = convert_to_suitable_format(estimated_time2)
                    crack_time2 = get_estimated_time(estimated_time2, time_type, 2)
                    return crack_time1, crack_time2


    def estimate_crack_time_engine1(self, password_length, have_numbers, have_upper, have_lower, have_symbols):
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
        combinations = password_type ** password_length  # ** - means pow
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

    def check_evil_twin(self, ssid):
        """function check if there is another access point in the close range of the server
        which have the same ssid as the user's network
        :param ssid: the ssid of the user's network
        :type ssid: string
        :return: if there is access point with the same ssid
        :rtype: boolean
        """
        command = "nmcli -f SSID device wifi list"
        all_access_points = subprocess.run(command, shell=True, stdout=subprocess.PIPE, text=True).stdout
        return all_access_points.count(ssid + '\n') > 1


    def get_warning_ssid_open(router_ip):
        """function return all the steps you need to hide your wifi access
        :param router_ip: the router's ip
        :type router_ip: string
        :return: the steps you need to do for hiding your wifi
        :rtype: string"""
        warning = ""
        warning += "WARNING!\nEveryone have access to your wifi"
        warning += "In case you want the devices need also know your wifi name in order to connect it"
        warning += "Just follow the next steps:\n1.Open http://" + router_ip
        warning += "from a browser. Enter your 'User Name' and 'Password' fields to log in to your router"
        warning += "If you have issues logging in the router's website, contact your router's manufacturer\n"
        warning += '2. Select "Wireless" then "Basic Wireless Settings" from the menus.'
        warning += 'Set "SSID Broadcast" to "Disabled" if your router operates on a dual band,'
        warning += 'Set "SSID Broadcast" to "Disabled\n3. Click "Save Settings" to hide your SSID.\n'
        warning += "Pay attention, that steps are not the same for all kind of routers, so if you can't find the exact"
        warning += "key words, try looking for similar ones instead"
        return warning

    def print_conclusion(self, conclusion):
        """function print the conclusion of the network scanner
        :param conclusion: the conclusion of the scan
        :type conclusion: list
        :return: none"""
        print("*****************************conclusion*****************************")
        print("evil twin result:")
        print(conclusion[0])
        if len(conclusion) == 1:
            print(conclusion[1])
        else:
            if conclusion[1] != "--":  # not sure, need check
                print(get_warning_ssid_open())
            if conclusion[2]:
                print("your wifi name is a common one, for your safety, try changing it to less common name")
            if conclusion[3] is tuple:
                print("first result of engine calculate estimated time: ")
                print(conclusion[3][0])
                print("second result of engine calculate estimated time: ")
                print(conclusion[3][1])
                print("remember good and strong password must contain at least 8 characters, including", end=" ")
                print("numbers, both upper and lower letters, and special symbols like: * or &")
            else:
                print(conclusion[3])
            if conclusion[4] is bool:
                if conclusion[4]:
                    print("your username for the router is a common username, try to change it in your router's website")
                else:
                    print("Good News: your username is not in the common usernames list, so you're safe in this perspective")
            if conclusion[5] is bool:
                if conclusion[5]:
                    print("your password for the router is a common password, try to change it in your router's website")
                else:
                    print("Good News: your password is not in the common passwords list, so you're safe in this perspective")



        ssid = get_ssid()
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
