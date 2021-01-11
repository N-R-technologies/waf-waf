import re
from detective.toolbox.risk_levels import RiskLevels


class BasicChecks:
    @staticmethod
    def include_site(request):
        return RiskLevels.CRITICAL if re.search(r"(?:\binclude\s*\([^)]*(ht|f)tps?:\/\/)", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def q_mark_after_url(request):
        return RiskLevels.CRITICAL if re.search(r"(?:ft|htt)ps?.*\?+$", request)\
            else RiskLevels.NO_RISK
