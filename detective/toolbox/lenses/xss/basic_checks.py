import re
from detective.toolbox.risk_levels import RiskLevels


class BasicChecks:
    @staticmethod
    def script_tag(request):
        """
        This function will check if the user tries to inject a script as input
        :param request: the user's request
        :type request: string
        :return:: the dangerous level according the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.CRITICAL if re.search(r"""<\s*script\s*>.+?<\s*/\s*script\s*>""", request) \
            else RiskLevels.NO_RISK
