import re
from urllib.parse import urlparse
from risk_level import RiskLevel


class XxeCheck:
    @staticmethod
    def information_disclosure(statement):
        """
        This function will check if the user tries to get information
        from the server machine by injecting xml content to the xml parser
        :param statement: the user's request
        :type statement: string
        :return: the dangerous level according the findings
        :rtype: int
        """
        return RiskLevel.MEDIUM_RISK if re.search(r"""<!\s*(?P<component>element|entity\s+.*system\s+)""", statement) \
            else RiskLevel.NO_RISK

    @staticmethod
    def blind_xxe(statement):
        """
        This function will check if the user try to send his information disclosure to some server or website
        :param statement: the user's request
        :return the dangerous level according the findings
        :rtype: int
        """
        result = re.search(r""".*?(?:'|\")(?P<url>.*?)(?:'|\")""", statement)
        if result:
            url = result.group("url")
            if url:
                parse_result = urlparse(url)
                if parse_result.scheme != '' and parse_result.netloc != '':
                    return RiskLevel.MEDIUM_RISK
        return RiskLevel.NO_RISK

    @staticmethod
    def xxe_comments(statement):
        """
        This function will check if the request contains some xxe comment tags
        :param statement: the user's request
        :type statement: string
        :return the dangerous level according the findings
        :rtype: int
        """
        return RiskLevel.LOW_RISK if re.search(r"""<!(\[cdata\[|\-\-)""", statement) else RiskLevel.NO_RISK

    @staticmethod
    def billion_laughs(statement):
        """
        This function will check if the request contains "billion"
        occurrences of a single entity, one after another
        :param statement: the user's request
        :type statement: string
        :return the dangerous level according the findings
        :rtype: int
        """
        return RiskLevel.LARGE_RISK if \
            re.search(r"""<\s*!\s*entity\s+(?P<variable>.+?)\s+.+\s*>.+?\s*(?:&(?P=variable);\s*){3,}?""", statement) \
            else RiskLevel.NO_RISK
