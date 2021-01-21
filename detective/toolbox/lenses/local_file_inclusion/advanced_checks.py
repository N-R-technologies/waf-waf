import re
from detective.toolbox.risk_levels import RiskLevels


class AdvancedChecks:
    @staticmethod
    def malicious_parameters(request) -> RiskLevels:
        malicious_parameters = ["cat", "dir", "action", "board", "date", "detail", "file", "download",
                                "path", "folder", "prefix", "include", "page", "inc", "locate", "show",
                                "doc", "site", "type", "view", "content", "document", "layout", "mod", "conf"]
        detect_parameters = re.findall(r"""\?(?P<parameter>.+)=\s*.+?""", request)
        if detect_parameters is not None:
            white_spaces = re.compile(r"\s+")
            for parameter in detect_parameters:
                parameter = re.sub(white_spaces, '', parameter)
                for extension in malicious_parameters:
                    if extension in parameter:
                        return RiskLevels.MODERATE
        return RiskLevels.NO_RISK
