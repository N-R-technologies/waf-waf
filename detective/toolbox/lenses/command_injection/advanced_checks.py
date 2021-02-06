import re
from detective.toolbox.risk_levels import RiskLevels

REGEX_QUERY = 0
RISK_LEVEL = 1


class AdvancedChecks:
    @staticmethod
    def malicious_commands(request) -> RiskLevels:
        malicious_commands = (("(?:whoami|ls)", RiskLevels.MODERATE), ("(?:uname\s+-a)", RiskLevels.CRITICAL),
                              ("i[fp]config(?:\s+\/all)?", RiskLevels.CATASTROPHIC), ("netstat\s+-an", RiskLevels.CRITICAL),
                              ("(?:(?:rm|ps)\s+-.+|tasklist)", RiskLevels.CATASTROPHIC), ("(?:ping|echo)\s+.+", RiskLevels.SLIGHT),
                              ("nslookup\s+.+", RiskLevels.CATASTROPHIC), ("cat.*/etc/.+", RiskLevels.CATASTROPHIC),
                              ("nc\s+-", RiskLevels.MODERATE), ("pwd($|\s+)", RiskLevels.MODERATE), ("cat.*/", RiskLevels.SLIGHT),
                              ("id\s*(-g|-G|-n|-r|-u)", RiskLevels.CRITICAL), ("touch|rm|cp", RiskLevels.MODERATE), ("sleep\s+\d", RiskLevels.SLIGHT),
                              ("php\s*-[abcndefhilmrstvwz]", RiskLevels.CRITICAL), ("php\s*--(ini|rf|rc|re|rz|ri)", RiskLevels.CRITICAL),
                              ("php\s+-version", RiskLevels.CRITICAL), ("curl|wget", RiskLevels.CRITICAL))
        detect_commands_result = re.findall(r"""(?:&{1,2}|\|{1,2}|;|\n|0x0a)\s*(?:`|\$\s*\()?(?P<command>(?:(?!&|\||\n|0x0a|;).)+)""", request)
        max_risk_level = 0
        for command in detect_commands_result:
            for malicious_command in malicious_commands:
                if re.search(malicious_command[REGEX_QUERY], command) and malicious_command[RISK_LEVEL] > max_risk_level:
                    max_risk_level = malicious_command[RISK_LEVEL]
        return max_risk_level
