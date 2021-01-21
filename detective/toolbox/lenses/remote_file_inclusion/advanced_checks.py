import re
import toml
from urllib.parse import urlparse
from detective.toolbox.risk_levels import RiskLevels


class AdvancedChecks:
    @staticmethod
    def off_site_url(request) -> RiskLevels
        ip_redirect_result = re.findall(r"""(?:ht|f)tps?:\/\/(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""", request)
        if ip_redirect_result is not None:
            for ip_address in ip_redirect_result:
                for num in ip_address.split('.'):
                    if not '0' <= num <= "255":
                        return RiskLevels.NO_RISK
            return RiskLevels.CATASTROPHIC
        detect_url_result = re.findall(r"""(?:ht|f)tps?://(?P<url>.*)""", request)
        if detect_url_result is not None:
            server_url = toml.load("server_info.toml")["host"]
            for url in detect_url_result:
                parse_result = urlparse(url)
                if parse_result.netloc != '' and server_url not in url:
                    return RiskLevels.CRITICAL
        return RiskLevels.NO_RISK

    @staticmethod
    def malicious_file_injection(request) -> RiskLevels:
        malicious_extensions = (".shadow", ".zip", ".exe", ".djvu", ".djvur", ".djvuu", ".udjvu", ".uudjvu", ".djvuq",
                               ".djvus", ".djvur", ".djvut", ".pdff", ".tro", ".tfude", ".tfudet", ".tfudeq", ".rumba",
                               ".adobe", ".adobee", ".blower", ".promos", ".promoz", ".promorad", ".promock",
                               ".promok", ".promorad2", ".kroput", ".kroput1", ".pulsar1", ".kropun1", ".charck",
                               ".klope", ".kropun", ".charcl", ".doples", ".luces", ".luceq", ".chech", ".proden",
                               ".drume", ".tronas", ".trosak", ".grovas", ".grovat", ".roland", ".refols", ".raldug",
                               ".etols", ".guvara", ".browec", ".norvas", ".moresa", ".vorasto", ".hrosas", ".kiratos",
                               ".todarius", ".hofos", ".roldat", ".dutan", ".sarut", ".fedasot", ".berost", ".forasom",
                               ".fordan", ".codnat", ".codnat1", ".bufas", ".dotmap", ".radman", ".ferosas", ".rectot",
                               ".skymap", ".mogera", ".rezuc", ".stone", ".redmat", ".lanset", ".davda", ".poret",
                               ".pidom", ".pidon", ".heroset", ".boston", ".muslat", ".gerosan", ".vesad", ".horon",
                               ".neras", ".truke", ".dalle", ".lotep", ".nusar", ".litar", ".besub", ".cezor", ".lokas", ".godes",
                               ".budak", ".vusad", ".herad", ".berosuce", ".gehad", ".gusau", ".madek", ".darus", ".tocue",
                               ".lapoi", ".todar", ".dodoc", ".bopador", ".novasof", ".ntuseg", ".ndarod",
                               ".access", ".format", ".nelasod", ".mogranos", ".cosakos", ".nvetud", ".lotej",
                               ".kovasoh", ".prandel", ".zatrov", ".masok", ".brusaf", ".londec", ".krusop",
                               ".mtogas", ".nasoh", ".nacro", ".pedro", ".nuksus", ".vesrato", ".masodas",
                               ".cetori", ".stare", ".carote", ".gero", ".hese", ".seto", ".peta", ".moka",
                               ".kvag", ".karl", ".nesa", ".noos", ".kuub", ".reco", ".bora")
        detect_url_result = re.findall(r"""(ht|f)tps?://(?P<url>.*)""", request)
        if detect_url_result is not None:
            for url in detect_url_result:
                for extension in malicious_extensions:
                    if extension in url:
                        return RiskLevels.CRITICAL
        return RiskLevels.NO_RISK
