import re
import toml
from urllib.parse import urlparse
from detective.toolbox import RiskLevels


class AdvancedChecks:
    @staticmethod
    def blind_xxe(request) -> RiskLevels:
        urls_found = re.findall(r"""!\s*entity\s+.+?\s+system\s+(?:\"|')(?P<url>.+?|)(?:\"|')""", request)
        if urls_found is not None:
            server_url = toml.load("waf_data/server_info.toml")["host"]
            white_spaces = re.compile(r"\s+")
            for url in urls_found:
                parse_result = urlparse(re.sub(white_spaces, '', url))
                if parse_result.netloc != '' and server_url not in url:
                    return RiskLevels.CATASTROPHIC
        return RiskLevels.NO_RISK

    @staticmethod
    def inject_file(request) -> RiskLevels:
        malicious_extensions = (".shadow", ".zip", ".exe", ".djvu", ".djvur", ".djvuu", ".udjvu", ".uudjvu", ".djvuq", ".djvus",
                                ".djvur", ".djvut", ".pdff", ".tro", ".tfude", ".tfudet", ".tfudeq", ".rumba",
                                ".adobe", ".adobee", ".blower", ".promos", ".promoz", ".promorad", ".promock",
                                ".promok", ".promorad2", ".kroput", ".kroput1", ".pulsar1", ".kropun1", ".charck",
                                ".klope", ".kropun", ".charcl", ".doples", ".luces", ".luceq", ".chech", ".proden",
                                ".drume", ".tronas", ".trosak", ".grovas", ".grovat", ".roland", ".refols", ".raldug",
                                ".etols", ".guvara", ".browec", ".norvas", ".moresa", ".vorasto", ".hrosas", ".kiratos",
                                ".todarius", ".hofos", ".roldat", ".dutan", ".sarut", ".fedasot", ".berost", ".forasom",
                                ".fordan", ".codnat", ".codnat1", ".bufas", ".dotmap", ".radman", ".ferosas", ".rectot",
                                ".skymap", ".mogera", ".rezuc", ".stone", ".redmat", ".lanset", ".davda", ".poret",
                                ".pidom",".pidon", ".heroset", ".boston", ".muslat", ".gerosan", ".vesad", ".horon", ".neras",
                                ".truke", ".dalle", ".lotep", ".nusar", ".litar", ".besub", ".cezor", ".lokas", ".godes", ".budak",
                                ".vusad", ".herad", ".berosuce", ".gehad", ".gusau", ".madek", ".darus", ".tocue",
                                ".lapoi", ".todar", ".dodoc", ".bopador", ".novasof", ".ntuseg", ".ndarod",
                                ".access", ".format", ".nelasod", ".mogranos", ".cosakos", ".nvetud", ".lotej",
                                ".kovasoh", ".prandel", ".zatrov", ".masok", ".brusaf", ".londec", ".krusop",
                                ".mtogas", ".nasoh", ".nacro", ".pedro", ".nuksus", ".vesrato", ".masodas",
                                ".cetori", ".stare", ".carote", ".gero", ".hese", ".seto", ".peta", ".moka",
                                ".kvag", ".karl", ".nesa", ".noos", ".kuub", ".reco", ".bora")
        files = re.findall(r"""!\s*entity\s+.+?\s+system\s+(?:\"|')(?P<file_name>.+?|)(?:\"|')""", request)
        for file in files:
            for malicious_extension in malicious_extensions:
                if malicious_extension in file:
                    return RiskLevels.CATASTROPHIC
        return RiskLevels.NO_RISK
