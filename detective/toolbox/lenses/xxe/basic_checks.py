import re
from detective.toolbox import RiskLevels


class BasicChecks:
    @staticmethod
    def data_disclosure(request) -> RiskLevels:
        return RiskLevels.CRITICAL \
            if re.search(r"""!\s*entity\s+.+?\s+system\s+(?P<quote>\"|')(?:file:///etc|php://filter/|expect://).*?(?P=quote)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def billion_laughs(request) -> RiskLevels:
        return RiskLevels.CATASTROPHIC \
            if re.search(r"""!\s*entity\s+(?P<variable>.+?)\s+.+?\s*>.+?\s*(?:&(?P=variable);\s*){3,}?""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def endless_file(request) -> RiskLevels:
        return RiskLevels.CATASTROPHIC \
            if re.search(r"""!\s*entity\s+.+?\s+system\s+(?P<quote>\"|')file:///dev.*?(?P=quote)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def xinclude(request) -> RiskLevels:
        return RiskLevels.CATASTROPHIC \
            if re.search(r"""<\s*xi:\s*include\s+(?:.+\s+)*?href\s*=\s*(?P<quote>\"|')file:///etc.*?(?P=quote)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def svg_uploading(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""<\s*image\s+xlink:\s*(?:.+\s+)*?href\s*=\s*(?P<quote>\"|')(?:file:///etc.*?|expect://.+?)(?P=quote)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def base64_encoded(request) -> RiskLevels:
        return RiskLevels.SLIGHT \
            if re.search(r"""!\s*entity\s+.+?\s+system\s+(?P<quote>\"|')data://text/plain;base64.*?(?P=quote)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def utf7(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""encoding=\"utf-7\".*?(system|entity|doctype|element)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def xxe_comment(request) -> RiskLevels:
        return RiskLevels.NEGLIGIBLE \
            if re.search(r"""<\s*!(\[cdata\[|\-\-)""", request) else RiskLevels.NO_RISK
