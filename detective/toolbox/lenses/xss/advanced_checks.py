import re
import toml
from urllib.parse import urlparse
from detective.toolbox import RiskLevels


class AdvancedChecks:
    @staticmethod
    def blind_xss(request) -> RiskLevels:
        urls_found = re.findall(r"""(?:<|')\s*(?:i?frame|img|embed|ipt)(?:/|\s).*?src\s*=\s*(?:(?:\"|'|`)\s*)?(?:<\s*)?(?P<url>[^\"'`<>]+)""", request)
        urls_found.extend(re.findall(r"""<\s*link(?:/|\s).*?href\s*=\s*(?:(?:\"|'|`)\s*)?(?:<\s*)?(?P<url>[^\"'`<>]+)""", request))
        urls_found.extend(re.findall(r"""<\s*meta(?:/|\s).*?content\s*=\s*(?:(?:\"|'|`)\s*)?(?:<\s*)?(?P<url>[^\"'`<>]+)""", request))
        urls_found.extend(re.findall(r"""<\s*object(?:/|\s).*?data\s*=\s*(?:(?:\"|'|`)\s*)?(?:<\s*)?(?P<url>[^\"'`<>]+)""", request))
        urls_found.extend(re.findall(r"""<\s*style(?:/|\s)*>.*?@\s*import\s*(?:(?:\"|'|`)\s*)?(?:<\s*)?(?P<url>[^\"'`<>]+)""", request))
        urls_found.extend(re.findall(r"""<\s*style(?:/|\s)*>.*?body\s*{\s*-moz-binding\s*:[^(]+?\((?:(?:\"|'|`)\s*)?(?:<\s*)?(?P<url>[^\"'`<>]+)""", request))
        urls_found.extend(re.findall(r"""<\s*a(?:/|\s).*?href\s*=\s*(?:(?:\"|'|`)\s*)?(?:javascript\s*:\s*document\.location\s*=\s*(?:(?:\"|'|`)\s*)?)?(?:<\s*)?(?P<url>[^\"'`<>]+)""", request))
        if len(urls_found) > 0:
            server_url = toml.load("waf_data/server_info.toml")["host"]
            white_spaces = re.compile(r"\s+")
            for url in urls_found:
                parse_result = urlparse(re.sub(white_spaces, '', url))
                if parse_result.netloc != '' and server_url not in url:
                    return RiskLevels.CATASTROPHIC
        return RiskLevels.NO_RISK
