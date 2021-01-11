import re
from detective.toolbox.risk_levels import RiskLevels


class AdvancedChecks:
    @staticmethod
    def blind_xxe(request):
        """
        This function will
        :param request: the user's request
        :type request: string
        :return: the dangerous level according the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.NO_RISK if re.search(r"""""", request) else RiskLevels.NO_RISK
