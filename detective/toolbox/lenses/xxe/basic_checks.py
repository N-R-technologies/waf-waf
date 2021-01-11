import re
from detective.toolbox.risk_levels import RiskLevels


class BasicChecks:
    @staticmethod
    def data_disclosure(request):
        """
        This function will check if the user tries to get system information
        from the server machine by injecting xml content to the xml parser
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.CRITICAL \
            if re.search(r"""!\s*entity\s+.+?\s+system\s+(?P<quote>\"|')(?:file:///etc|php://filter/|expect://).*?(?P=quote)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def billion_laughs(request):
        """
        This function will check if the user tries to assign
        potentially endless variables to the system
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.CATASTROPHIC if re.search(r"""!\s*entity\s+(?P<variable>.+?)\s+.+?\s*>.+?\s*(?:&(?P=variable);\s*){3,}?""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def endless_file(request):
        """
        This function will check if the user tries to assign
        potentially endless file to the system
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.CATASTROPHIC if re.search(r"""!\s*entity\s+.+?\s+system\s+(?P<quote>\"|')file:///dev.*?(?P=quote)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def xinclude(request):
        """
        This function will check if the user tries to specify a local
        system file using xinclude, hence retrieve the file
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.CATASTROPHIC if re.search(r"""<\s*xi:\s*include\s+(?:.+\s+)*?href\s*=\s*(?P<quote>\"|')file:///etc.*?(?P=quote)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def svg_uploading(request):
        """
        This function will check if the user tries to either retrieve a local system
        file or execute a bash command through the xml parser via uploading svg image
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.MODERATE \
            if re.search(r"""<\s*image\s+xlink:\s*(?:.+\s+)*?href\s*=\s*(?P<quote>\"|')(?:file:///etc.*?|expect://.+?)(?P=quote)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def base64_encoded(request):
        """
        This function will check if the user tries to encode files
        with base64 and then retrieve them on the receiving end
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"""!\s*entity\s+.+?\s+system\s+(?P<quote>\"|')data://text/plain;base64.*?(?P=quote)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def utf7(request):
        """
        This function will check if the user tries to write
        an XML document encoded with UTF-7
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.MODERATE if re.search(r"""encoding=\"utf-7\".*?(system|entity|doctype|element)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def xxe_comments(request):
        """
        This function will check if the user's request contains xxe comment tags
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.NEGLIGIBLE if re.search(r"""<\s*!(\[cdata\[|\-\-)""", request) else RiskLevels.NO_RISK
