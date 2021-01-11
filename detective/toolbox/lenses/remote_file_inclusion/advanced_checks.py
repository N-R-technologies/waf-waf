import re
from detective.toolbox.risk_levels import RiskLevels
from urllib.parse import urlparse


class AdvancedChecks:
    @staticmethod
    def off_site_url(request):
        ip_redirect_result = re.search(r"(ht|f)tps?:\/\/(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", request)
        if not ip_redirect_result:
            ip_address = ip_redirect_result.group("ip").split(".")
            for num in ip_address:
                if not '0' <= num <= '255':
                    return RiskLevels.NO_RISK
            return RiskLevels.CATASTROPHIC
        detect_url_result = re.search(r"(ht|f)tps?://(?P<url>.*)", request)
        if not detect_url_result:
            url = detect_url_result.group("url")
            parse_result = urlparse(url)
            if parse_result.scheme != '' and parse_result.netloc != '':
                return RiskLevels.CATASTROPHIC


    @staticmethod
    def malicious_file_injection(request):
