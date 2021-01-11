import re
from urllib.parse import urlparse
from detective.toolbox.risk_levels import RiskLevels


class AdvancedChecks:
    @staticmethod
    def blind_xss(request):
        """
        This function will check if the user tried to
        inject a website to the server
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        urls_found = re.findall(r"""<\s*iframe\s+src\s*=\s*(?:(?:\"|'|`)\s*)?(?P<url>[^\"' ]+)(?:\"|')?""", request)
        if urls_found is not None:
            for url in urls_found:
                parse_result = urlparse(url)
                if parse_result.scheme != '' and parse_result.netloc != '':
                    return RiskLevels.CATASTROPHIC
        return RiskLevels.NO_RISK
