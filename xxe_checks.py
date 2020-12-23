import re
from urllib.parse import urlparse
from risk_level import RiskLevel


class XxeChecks:
    @staticmethod
    def data_disclosure(statement):
        """
        This function will check if the user tries to get system information
        from the server machine by injecting xml content to the xml parser
        :param statement: the user's request
        :type statement: string
        :return: the dangerous level according the findings
        :rtype: int
        """
        return RiskLevel.LARGE_RISK \
            if re.search(r"""!\s*entity\s+.+?\s+system\s+(?:'|\")(?:file:///etc|php://filter/|expect://).*?(?:'|\")""", statement) \
            else RiskLevel.NO_RISK

    @staticmethod
    def blind_xxe(statement):
        """
        This function will check if the user tries to send his
        information disclosure to some server or website
        :param statement: the user's request
        :return the dangerous level according the findings
        :rtype: int
        """
        xml_entities = re.findall(r"""!\s*entity\s+.+?\s+system\s+(?:'|\")(?P<url>.+?|)(?:'|\")""", statement)
        if xml_entities is not None:
            for entity in xml_entities:
                parse_result = urlparse(entity)
                if parse_result.scheme != '' and parse_result.netloc != '':
                    return RiskLevel.LOW_RISK
        return RiskLevel.NO_RISK

    @staticmethod
    def denial_of_service(statement):
        """
        This function will check if the user tries to assign
        potentially endless variables to the system
        :param statement: the user's request
        :type statement: string
        :return the dangerous level according the findings
        :rtype: int
        """
        risk_level = RiskLevel.NO_RISK
        billion_laughs = re.search(r"""!\s*entity\s+(?P<variable>.+?)\s+.+?\s*>.+?\s*(?:&(?P=variable);\s*){3,}?""", statement)
        endless_file = re.search(r"""!\s*entity\s+.+?\s+system\s+(?:'|\")file:///dev.*?(?:'|\")""", statement)
        if billion_laughs is not None:
            risk_level += RiskLevel.LARGE_RISK
        if endless_file is not None:
            risk_level += RiskLevel.MEDIUM_RISK
        return risk_level

    @staticmethod
    def xinclude(statement):
        """
        This function will check if the user tries to specify a local
        system file using xinclude, hence retrieve the file
        :type statement: string
        :return the dangerous level according the findings
        :rtype: int
        """
        return RiskLevel.LARGE_RISK if re.search(r"""<\s*xi:\s*include\s+(?:.+\s+)*?href\s*=\s*(?:'|\")file:///etc.*?(?:'|\")""", statement) \
            else RiskLevel.NO_RISK

    @staticmethod
    def svg_uploading(statement):
        """
        This function will check if the user tries to either retrieve a local system
        file or execute a bash command through the xml parser via uploading svg image
        :param statement: the user's request
        :type statement: string
        :return the dangerous level according the findings
        :rtype: int
        """
        return RiskLevel.MEDIUM_RISK \
            if re.search(r"""<\s*image\s+xlink:\s*(?:.+\s+)*?href\s*=\s*(?:'|\")(?:file:///etc.*?|expect://.+?)(?:'|\")""", statement) \
            else RiskLevel.NO_RISK

    @staticmethod
    def base64_encoded(statement):
        """
        This function will check if the user tries to encode files
        with base64 and then retrieve them on the receiving end
        :type statement: string
        :return the dangerous level according the findings
        :rtype: int
        """
        return RiskLevel.LOW_RISK if re.search(r"""!\s*entity\s+.+?\s+system\s+(?:'|\")data://text/plain;base64.*?(?:'|\")""", statement) \
            else RiskLevel.NO_RISK

    @staticmethod
    def xxe_comments(statement):
        """
        This function will check if the  user's request contains xxe comment tags
        :param statement: the user's request
        :type statement: string
        :return the dangerous level according the findings
        :rtype: int
        """
        return RiskLevel.VERY_LOW_RISK if re.search(r"""<\s*!(\[cdata\[|\-\-)""", statement) else RiskLevel.NO_RISK
