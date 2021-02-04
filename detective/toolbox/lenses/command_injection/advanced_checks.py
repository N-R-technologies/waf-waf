import re
from detective.toolbox.risk_levels import RiskLevels

REGEX_QUERY = 0
RISK_LEVEL = 1


class AdvancedChecks:
    @staticmethod
    def malicious_commands(request) -> RiskLevels:
        malicious_commands = (("(?:whoami|ls)", RiskLevels.MODERATE), ("(?:uname\s+-a|ver)", RiskLevels.CRITICAL),
                              ("i[fp]config(?:\s+\/all)?", RiskLevels.CATASTROPHIC), ("netstat\s+-an", RiskLevels.CRITICAL),
                              ("(?:(?:rm|ps)\s+-.+|tasklist)", RiskLevels.CATASTROPHIC), ("(?:ping|echo)\s+.+", RiskLevels.SLIGHT),
                              ("nslookup\s+.+", RiskLevels.CATASTROPHIC), ("cat\s+/etc/.+", RiskLevels.CATASTROPHIC))
        detect_commands_result = re.findall(r"""(?:&{1,2}|\|{1,2}|;|\n|0x0a)\s*(?:`|\$\s*\()?(?P<command>(?:(?!&|\||\n|0x0a).)+)""", request)
        for command in detect_commands_result:
            for malicious_command in malicious_commands:
                if re.search(malicious_command[REGEX_QUERY], command):
                    return malicious_command[RISK_LEVEL]
        return RiskLevels.NO_RISK
