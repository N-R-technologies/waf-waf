import re
from detective.toolbox import RiskLevels


class BasicChecks:
    @staticmethod
    def include_site(request) -> RiskLevels:
        return RiskLevels.CRITICAL if re.search(r"""(?:\binclude\s*\([^)]*(?:ht|f)tps?:\/\/)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def q_mark_after_url(request) -> RiskLevels:
        return RiskLevels.CRITICAL if re.search(r"""(?:ht|f)tps?.*\?+$""", request)\
            else RiskLevels.NO_RISK
