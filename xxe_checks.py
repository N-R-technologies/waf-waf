import re
from urllib.parse import urlparse
from risk_level import RiskLevel


class XxeChecks:
    @staticmethod
    def data_disclosure(request):
        """
        This function will check if the user tries to get system information
        from the server machine by injecting xml content to the xml parser
        :param request: the user's request
        :type request: string
        :return: the dangerous level according the findings
        :rtype: integer
        """
        return RiskLevel.MEDIUM_RISK \
            if re.search(r"""!\s*entity\s+.+?\s+system\s+(?:'|\")(?:file:///etc|php://filter/|expect://).*?(?:'|\")""", request) \
            else RiskLevel.NO_RISK

    @staticmethod
    def blind_xxe(request):
        """
        This function will check if the user tries to send his
        information disclosure to some server or website
        :param request: the user's request
        :return the dangerous level according the findings
        :rtype: integer
        """
        urls_found = re.findall(r"""!\s*entity\s+.+?\s+system\s+(?:'|\")(?P<url>.+?|)(?:'|\")""", request)
        if urls_found is not None:
            for url in urls_found:
                parse_result = urlparse(url)
                return RiskLevel.LARGE_RISK if parse_result.scheme is not None and parse_result.netloc is not None \
                    else RiskLevel.NO_RISK

    @staticmethod
    def inject_file(request):
        malicious_extensions = [".shadow",".djvu",".djvur",".djvuu",".udjvu",".uudjvu",".djvuq",".djvus",
                              ".djvur",".djvut",".pdff",".tro",".tfude",".tfudet",".tfudeq",".rumba",
                              ".adobe",".adobee",".blower",".promos",".promoz",".promorad",".promock",
                              ".promok",".promorad2",".kroput",".kroput1",".pulsar1",".kropun1",".charck",
                              ".klope",".kropun",".charcl",".doples",".luces",".luceq",".chech",".proden",
                              ".drume",".tronas",".trosak",".grovas",".grovat",".roland",".refols",".raldug",
                              ".etols",".guvara",".browec",".norvas",".moresa",".vorasto",".hrosas",".kiratos",
                              ".todarius",".hofos",".roldat",".dutan",".sarut",".fedasot",".berost",".forasom",
                              ".fordan",".codnat",".codnat1",".bufas",".dotmap",".radman",".ferosas",".rectot",
                              ".skymap",".mogera",".rezuc",".stone",".redmat",".lanset",".davda",".poret",".pidom",
                              ".pidon",".heroset",".boston",".muslat",".gerosan",".vesad",".horon",".neras",".truke",
                              ".dalle",".lotep",".nusar",".litar",".besub",".cezor",".lokas",".godes",".budak",".vusad",
                              ".herad",".berosuce",".gehad",".gusau",".madek",".darus",".tocue",
                              ".lapoi",".todar",".dodoc",".bopador",".novasof",".ntuseg",".ndarod",
                              ".access",".format",".nelasod",".mogranos",".cosakos",".nvetud",".lotej",
                              ".kovasoh",".prandel",".zatrov",".masok",".brusaf",".londec",".krusop",
                              ".mtogas",".nasoh",".nacro",".pedro",".nuksus",".vesrato",".masodas",
                               ".cetori",".stare",".carote",".gero",".hese",".seto",".peta",".moka",
                               ".kvag",".karl",".nesa",".noos",".kuub",".reco",".bora"]
        files = re.findall(r"""!\s*entity\s+.+?\s+system\s+(?:'|\")(?P<file_name>.+?|)(?:'|\")""", request)
        for file in files:
            for malicious_extension in malicious_extensions:
                if malicious_extension in file:
                    return RiskLevel.LARGE_RISK

    @staticmethod
    def billion_laughs(request):
        """
        This function will check if the user tries to assign
        potentially endless variables to the system
        :param request: the user's request
        :type request: string
        :return the dangerous level according the findings
        :rtype: integer
        """
        return RiskLevel.LARGE_RISK if re.search(r"""!\s*entity\s+(?P<variable>.+?)\s+.+?\s*>.+?\s*(?:&(?P=variable);\s*){3,}?""", request) \
            else RiskLevel.NO_RISK

    @staticmethod
    def endless_file(request):
        """
        This function will check if the user tries to assign
        potentially endless file to the system
        :param request: the user's request
        :type request: string
        :return the dangerous level according the findings
        :rtype: integer
        """
        return RiskLevel.LARGE_RISK if re.search(r"""!\s*entity\s+.+?\s+system\s+(?:'|\")file:///dev.*?(?:'|\")""", request) \
            else RiskLevel.NO_RISK

    @staticmethod
    def xinclude(request):
        """
        This function will check if the user tries to specify a local
        system file using xinclude, hence retrieve the file
        :type request: string
        :return the dangerous level according the findings
        :rtype: integer
        """
        return RiskLevel.LARGE_RISK if re.search(r"""<\s*xi:\s*include\s+(?:.+\s+)*?href\s*=\s*(?:'|\")file:///etc.*?(?:'|\")""", request) \
            else RiskLevel.NO_RISK

    @staticmethod
    def svg_uploading(request):
        """
        This function will check if the user tries to either retrieve a local system
        file or execute a bash command through the xml parser via uploading svg image
        :param request: the user's request
        :type request: string
        :return the dangerous level according the findings
        :rtype: integer
        """
        return RiskLevel.MEDIUM_RISK \
            if re.search(r"""<\s*image\s+xlink:\s*(?:.+\s+)*?href\s*=\s*(?:'|\")(?:file:///etc.*?|expect://.+?)(?:'|\")""", request) \
            else RiskLevel.NO_RISK

    @staticmethod
    def base64_encoded(request):
        """
        This function will check if the user tries to encode files
        with base64 and then retrieve them on the receiving end
        :type request: string
        :return the dangerous level according the findings
        :rtype: integer
        """
        return RiskLevel.VERY_LOW_RISK if re.search(r"""!\s*entity\s+.+?\s+system\s+(?:'|\")data://text/plain;base64.*?(?:'|\")""", request) \
            else RiskLevel.NO_RISK

    @staticmethod
    def utf7(request):
        return RiskLevel.MEDIUM_RISK if re.search(r"""encoding=\"utf-7\".*?(system|entity|doctype|element)""", request) \
            else RiskLevel.NO_RISK

    @staticmethod
    def xxe_comments(request):
        """
        This function will check if the  user's request contains xxe comment tags
        :param request: the user's request
        :type request: string
        :return the dangerous level according the findings
        :rtype: integer
        """
        return RiskLevel.VERY_LOW_RISK if re.search(r"""<\s*!(\[cdata\[|\-\-)""", request) else RiskLevel.NO_RISK
