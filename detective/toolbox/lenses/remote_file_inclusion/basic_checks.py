import re
from detective.toolbox.risk_levels import RiskLevels


class BasicChecks:
    @staticmethod
    def include_site(request):
        """
        This function will check if the user tries to
        include a web site in his request
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.CRITICAL if re.search(r"""(?:\binclude\s*\([^)]*(?:ht|f)tps?:\/\/)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def q_mark_after_url(request):
        """
        This function will check if the user tries to
        put a question mark at the end of the url
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.CRITICAL if re.search(r"""(?:ht|f)tps?.*\?+$""", request)\
            else RiskLevels.NO_RISK
