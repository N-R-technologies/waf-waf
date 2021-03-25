import re
from detective.toolbox import RiskLevels


class BasicChecks:
    @staticmethod
    def preparation(request) -> list:
         return re.findall(r"""(?:&{1,2}|\|{1,2}|;|\n|0x0a)\s*(?:`|\$\s*\()?(?P<command>(?:(?!&|\||\n|0x0a|;|`|\)).)+)""", str(request))

    @staticmethod
    def server_information(potential_commands_list) -> RiskLevels:
        for command in potential_commands_list:
            if re.search("whoami|ls", command):
                return RiskLevels.MODERATE
        return RiskLevels.NO_RISK

    @staticmethod
    def server_sensitive_information(potential_commands_list) -> RiskLevels:
        for command in potential_commands_list:
            if re.search("(?:uname\s+-a)", command):
                return RiskLevels.CRITICAL
        return RiskLevels.NO_RISK

    @staticmethod
    def network_information(potential_commands_list) -> RiskLevels:
        for command in potential_commands_list:
            if re.search("i[fp]config(?:\s+/all)?", command):
                return RiskLevels.CATASTROPHIC
        return RiskLevels.NO_RISK

    @staticmethod
    def network_statistics(potential_commands_list) -> RiskLevels:
        for command in potential_commands_list:
            if re.search("netstat\s+-an", command):
                return RiskLevels.CRITICAL
        return RiskLevels.NO_RISK

    @staticmethod
    def process_information(potential_commands_list) -> RiskLevels:
        for command in potential_commands_list:
            if re.search("ps\s+-.+|tasklist", command):
                return RiskLevels.CATASTROPHIC
        return RiskLevels.NO_RISK

    @staticmethod
    def basic_terminal_commands(potential_commands_list) -> RiskLevels:
        for command in potential_commands_list:
            if re.search("(?:ping|echo)\s+.+", command):
                return RiskLevels.SLIGHT
        return RiskLevels.NO_RISK

    @staticmethod
    def nslookup(potential_commands_list) -> RiskLevels:
        for command in potential_commands_list:
            if re.search("nslookup\s+.+", command):
                return RiskLevels.CATASTROPHIC
        return RiskLevels.NO_RISK

    @staticmethod
    def show_file(potential_commands_list) -> RiskLevels:
        for command in potential_commands_list:
            if re.search("cat\s+.+", command):
                return RiskLevels.SLIGHT
        return RiskLevels.NO_RISK

    @staticmethod
    def show_sensitive_file(potential_commands_list) -> RiskLevels:
        for command in potential_commands_list:
            if re.search("cat\s+.*/etc/.+", command):
                return RiskLevels.CATASTROPHIC
        return RiskLevels.NO_RISK

    @staticmethod
    def netcat_communication(potential_commands_list) -> RiskLevels:
        for command in potential_commands_list:
            if re.search("nc\s+-", command):
                return RiskLevels.MODERATE
        return RiskLevels.NO_RISK

    @staticmethod
    def server_running_path(potential_commands_list) -> RiskLevels:
        for command in potential_commands_list:
            if re.search("pwd", command):
                return RiskLevels.MODERATE
        return RiskLevels.NO_RISK

    @staticmethod
    def server_groups(potential_commands_list) -> RiskLevels:
        for command in potential_commands_list:
            if re.search("id\s*(-g|-G|-n|-r|-u|$)", command):
                return RiskLevels.CRITICAL
        return RiskLevels.NO_RISK

    @staticmethod
    def modify_file(potential_commands_list) -> RiskLevels:
        for command in potential_commands_list:
            if re.search("touch|cp|rm", command):
                return RiskLevels.MODERATE
        return RiskLevels.NO_RISK

    @staticmethod
    def delete_file(potential_commands_list) -> RiskLevels:
        for command in potential_commands_list:
            if re.search("rm\s*-", command):
                return RiskLevels.CRITICAL
        return RiskLevels.NO_RISK

    @staticmethod
    def server_sleep(potential_commands_list) -> RiskLevels:
        for command in potential_commands_list:
                if re.search("sleep\s+\d", command):
                    return RiskLevels.SLIGHT
        return RiskLevels.NO_RISK

    @staticmethod
    def php_single_char_flag(potential_commands_list) -> RiskLevels:
        for command in potential_commands_list:
            if re.search("php\s*-[abcndefhilmrstvwz]", command):
                return RiskLevels.CRITICAL
        return RiskLevels.NO_RISK

    @staticmethod
    def php_multiple_char_flag(potential_commands_list) -> RiskLevels:
        for command in potential_commands_list:
            if re.search("php\s*--(ini|rf|rc|re|rz|ri)", command):
                return RiskLevels.CRITICAL
        return RiskLevels.NO_RISK

    @staticmethod
    def php_info(potential_commands_list) -> RiskLevels:
        for command in potential_commands_list:
            if re.search("php\s+-version", command):
                return RiskLevels.MODERATE
        return RiskLevels.NO_RISK

    @staticmethod
    def upload_download_internet_files(potential_commands_list) -> RiskLevels:
        for command in potential_commands_list:
            if re.search("curl|wget", command):
                return RiskLevels.CATASTROPHIC
        return RiskLevels.NO_RISK
