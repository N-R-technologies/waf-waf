import re
from detective.toolbox.risk_levels import RiskLevels


class BasicChecks:
    @staticmethod
    def data_disclosure(request) -> RiskLevels:
        return RiskLevels.CRITICAL \
            if re.search(r"""!\s*entity\s+.+?\s+system\s+(?:'|\")(?:file:///etc|php://filter/|expect://).*?(?:'|\")""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def billion_laughs(request) -> RiskLevels:
        return RiskLevels.CATASTROPHIC if re.search(r"""!\s*entity\s+(?P<variable>.+?)\s+.+?\s*>.+?\s*(?:&(?P=variable);\s*){3,}?""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def endless_file(request) -> RiskLevels:
        return RiskLevels.CATASTROPHIC if re.search(r"""!\s*entity\s+.+?\s+system\s+(?:'|\")file:///dev.*?(?:'|\")""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def xinclude(request) -> RiskLevels:
        return RiskLevels.CATASTROPHIC if re.search(r"""<\s*xi:\s*include\s+(?:.+\s+)*?href\s*=\s*(?:'|\")file:///etc.*?(?:'|\")""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def svg_uploading(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""<\s*image\s+xlink:\s*(?:.+\s+)*?href\s*=\s*(?:'|\")(?:file:///etc.*?|expect://.+?)(?:'|\")""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def base64_encoded(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""!\s*entity\s+.+?\s+system\s+(?:'|\")data://text/plain;base64.*?(?:'|\")""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def utf7(request) -> RiskLevels:
        return RiskLevels.MODERATE if re.search(r"""encoding=\"utf-7\".*?(system|entity|doctype|element)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def xxe_comments(request) -> RiskLevels:
        return RiskLevels.NEGLIGIBLE if re.search(r"""<\s*!(\[cdata\[|\-\-)""", request) else RiskLevels.NO_RISK
