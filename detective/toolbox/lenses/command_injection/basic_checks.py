import re
from detective.toolbox.risk_levels import RiskLevels


class BasicChecks:

    @staticmethod
    def preparation(request) -> list:
        return re.findall(r"""(?:&{1,2}|\|{1,2}|;|\n|0x0a)\s*(?:`|\$\s*\()?(?P<command>(?:(?!&|\||\n|0x0a|;|`|\)).)+)""", request)

    @staticmethod
    def server_information(command) -> RiskLevels:
        return RiskLevels.MODERATE if re.search("(?:whoami|ls)", command)\
            else RiskLevels.NO_RISK

    @staticmethod
    def server_sensitive_information(command) -> RiskLevels:
        return RiskLevels.CRITICAL if re.search("(?:uname\s+-a)", command)\
            else RiskLevels.NO_RISK

    @staticmethod
    def network_information(command) -> RiskLevels:
        return RiskLevels.CATASTROPHIC if re.search("i[fp]config(?:\s+\/all)?", command)\
            else RiskLevels.NO_RISK

    @staticmethod
    def network_statistics(command) -> RiskLevels:
        return RiskLevels.CRITICAL if re.search("netstat\s+-an", command)\
            else RiskLevels.NO_RISK

    @staticmethod
    def process_information(command) -> RiskLevels:
        return RiskLevels.CATASTROPHIC if re.search("ps\s+-.+|tasklist", command)\
            else RiskLevels.NO_RISK

    @staticmethod
    def basic_terminal_commands(command) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search("(?:ping|echo)\s+.+", command)\
            else RiskLevels.NO_RISK

    @staticmethod
    def nslookup(command) -> RiskLevels:
        return RiskLevels.CATASTROPHIC if re.search("nslookup\s+.+", command)\
            else RiskLevels.NO_RISK

    @staticmethod
    def show_sensitive_file(command) -> RiskLevels:
        return RiskLevels.CATASTROPHIC if re.search("cat.*/etc/.+", command)\
            else RiskLevels.NO_RISK

    @staticmethod
    def netcat_communication(command) -> RiskLevels:
        return RiskLevels.MODERATE if re.search("nc\s+-", command) \
            else RiskLevels.NO_RISK

    @staticmethod
    def server_running_path(command) -> RiskLevels:
        return RiskLevels.MODERATE if re.search("pwd($|\s+)", command)\
            else RiskLevels.NO_RISK

    @staticmethod
    def show_file(command) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search("cat.*/", command)\
            else RiskLevels.NO_RISK

    @staticmethod
    def server_groups(command) -> RiskLevels:
        return RiskLevels.CRITICAL if re.search("id\s*(-g|-G|-n|-r|-u|$)", command)\
            else RiskLevels.NO_RISK

    @staticmethod
    def modify_file(command) -> RiskLevels:
        return RiskLevels.MODERATE if re.search("touch|cp|rm", command) \
            else RiskLevels.NO_RISK

    @staticmethod
    def delete_file(command) -> RiskLevels:
        return RiskLevels.CRITICAL if re.search("rm\s*-", command) \
            else RiskLevels.NO_RISK

    @staticmethod
    def sleep_server(command) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search("sleep\s+\d", command)\
            else RiskLevels.NO_RISK

    @staticmethod
    def php_single_char_flag(command) -> RiskLevels:
        return RiskLevels.CRITICAL if re.search("php\s*-[abcndefhilmrstvwz]", command)\
            else RiskLevels.NO_RISK

    @staticmethod
    def php_multiply_char_flag(command) -> RiskLevels:
        return RiskLevels.CRITICAL if re.search("php\s*--(ini|rf|rc|re|rz|ri)", command)\
            else RiskLevels.NO_RISK

    @staticmethod
    def php_info(command) -> RiskLevels:
        return RiskLevels.MODERATE if re.search("php\s+-version", command)\
            else RiskLevels.NO_RISK

    @staticmethod
    def upload_download_files_from_internet(command) -> RiskLevels:
        return RiskLevels.CATASTROPHIC if re.search("curl|wget", command)\
            else RiskLevels.NO_RISK
