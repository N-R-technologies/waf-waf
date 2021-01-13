import re
from detective.toolbox.risk_levels import RiskLevels
from urllib.parse import urlparse
import toml


class AdvancedChecks:
    @staticmethod
    def off_site_url(request):
        """
        function check if the user try to redirect the page to malicious url address
        :param request: the user's request
        :type request: str
        :return: the dangerous level according the findings if found, zero if not
        :rtype: enum RiskLevels
        """
        ip_redirect_result = re.search(r"(:?ht|f)tps?:\/\/(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", request)
        if ip_redirect_result:
            ip_address = ip_redirect_result.group("ip").split(".")
            for num in ip_address:
                if not '0' <= num <= '255':
                    return RiskLevels.NO_RISK
            return RiskLevels.CATASTROPHIC
        detect_url_result = re.search(r"(?:ht|f)tps?://(?P<url>.*)", request)
        if detect_url_result:
            parse_result = urlparse(detect_url_result.group("url"))
            server_url = toml.load("server_info.toml")["host"]
            if parse_result.netloc != '' and server_url not in detect_url_result:
                # check if the user try to connect to real url, that is not suburl of the current url
                return RiskLevels.CRITICAL
            return RiskLevels.NO_RISK

    @staticmethod
    def malicious_file_injection(request):
        """
        function check if the user try to redirect the page to outside url
        that contains some malicious file
        :param request: the user's request
        :type request: str
        :return: the dangerous level according the findings if found, zero if not
        :rtype: enum RiskLevels
        """
        malicious_extensions = [".shadow", ".zip", ".exe", ".djvu", ".djvur", ".djvuu", ".udjvu", ".uudjvu", ".djvuq",
                               ".djvus",
                               ".djvur", ".djvut", ".pdff", ".tro", ".tfude", ".tfudet", ".tfudeq", ".rumba",
                               ".adobe", ".adobee", ".blower", ".promos", ".promoz", ".promorad", ".promock",
                               ".promok", ".promorad2", ".kroput", ".kroput1", ".pulsar1", ".kropun1", ".charck",
                               ".klope", ".kropun", ".charcl", ".doples", ".luces", ".luceq", ".chech", ".proden",
                               ".drume", ".tronas", ".trosak", ".grovas", ".grovat", ".roland", ".refols", ".raldug",
                               ".etols", ".guvara", ".browec", ".norvas", ".moresa", ".vorasto", ".hrosas", ".kiratos",
                               ".todarius", ".hofos", ".roldat", ".dutan", ".sarut", ".fedasot", ".berost", ".forasom",
                               ".fordan", ".codnat", ".codnat1", ".bufas", ".dotmap", ".radman", ".ferosas", ".rectot",
                               ".skymap", ".mogera", ".rezuc", ".stone", ".redmat", ".lanset", ".davda", ".poret",
                               ".pidom", ".pidon", ".heroset", ".boston", ".muslat", ".gerosan", ".vesad", ".horon",
                               ".neras",
                               ".truke", ".dalle", ".lotep", ".nusar", ".litar", ".besub", ".cezor", ".lokas", ".godes",
                               ".budak",
                               ".vusad", ".herad", ".berosuce", ".gehad", ".gusau", ".madek", ".darus", ".tocue",
                               ".lapoi", ".todar", ".dodoc", ".bopador", ".novasof", ".ntuseg", ".ndarod",
                               ".access", ".format", ".nelasod", ".mogranos", ".cosakos", ".nvetud", ".lotej",
                               ".kovasoh", ".prandel", ".zatrov", ".masok", ".brusaf", ".londec", ".krusop",
                               ".mtogas", ".nasoh", ".nacro", ".pedro", ".nuksus", ".vesrato", ".masodas",
                               ".cetori", ".stare", ".carote", ".gero", ".hese", ".seto", ".peta", ".moka",
                               ".kvag", ".karl", ".nesa", ".noos", ".kuub", ".reco", ".bora"]
        detect_url_result = re.search(r"(ht|f)tps?://(?P<url>.*)", request)
        if detect_url_result:
            url = detect_url_result.group("url")
            for extension in malicious_extensions:
                if extension in url:
                    return RiskLevels.CRITICAL
        return RiskLevels.NO_RISK

