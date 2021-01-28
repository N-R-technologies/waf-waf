import re
from detective.toolbox.risk_levels import RiskLevels


class AdvancedChecks:
    @staticmethod
    def malicious_parameters(request) -> RiskLevels:
        malicious_parameters = ("cat", "dir", "action", "board", "date", "detail", "file", "download",
                                "path", "folder", "prefix", "include", "page", "inc", "locate", "show",
                                "doc", "site", "type", "view", "content", "document", "layout", "mod", "conf")
        detect_parameters_result = re.findall(r"""\?(?P<parameter>.+)=\s*.+?""", request)
        if detect_parameters_result is not None:
            white_spaces = re.compile(r"\s+")
            for parameter in detect_parameters_result:
                parameter = re.sub(white_spaces, '', parameter)
                for malicious_parameter in malicious_parameters:
                    if malicious_parameter in parameter:
                        return RiskLevels.SLIGHT
        return RiskLevels.NO_RISK