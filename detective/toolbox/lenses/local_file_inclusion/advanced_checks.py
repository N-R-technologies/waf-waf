import re
from detective.toolbox.risk_levels import RiskLevels


class AdvancedChecks:
    @staticmethod
    def malicious_parameters(request) -> RiskLevels:
        malicious_parameters = ("cat", "dir", "action", "board", "date", "detail", "file", "download",
                                "path", "folder", "prefix", "include", "inc", "locate", "show", "doc",
                                "site", "type", "view", "content", "document", "layout", "mod", "conf")
        detect_parameters_result = re.findall(r"""\?(?P<parameter>.+)=\s*.+?""", request)
        if len(detect_parameters_result) != 0:
            for parameter in detect_parameters_result:
                for malicious_parameter in malicious_parameters:
                    if malicious_parameter in parameter:
                        return RiskLevels.SLIGHT
        return RiskLevels.NO_RISK
