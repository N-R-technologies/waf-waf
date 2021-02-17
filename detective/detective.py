from importlib import import_module
from urllib.parse import unquote_plus
import detective.toolbox as toolbox
from attacks_logger.logger import AttacksLogger


class Detective:
    NEGLIGIBLE = 1/5
    SLIGHT = 2/5
    MODERATE = 3/5
    CRITICAL = 1
    CATASTROPHIC = 1
    INFO_INDEX = 2

    _multiplying_factors = ()
    _attacks_logger = AttacksLogger()

    def __init__(self):
        self._multiplying_factors = (self.NEGLIGIBLE, self.SLIGHT, self.MODERATE, self.CRITICAL, self.CATASTROPHIC)
        self._magnifying_glass = toolbox.MagnifyingGlass()
        self._assistant = toolbox.Assistant()
        self._lenses = []
        for lens in toolbox.lenses.__all__:
            lens_package = f"detective.toolbox.lenses.{lens}"
            basic_checks = getattr(import_module(".basic_checks", lens_package), "BasicChecks")
            advanced_checks = getattr(import_module(".advanced_checks", lens_package), "AdvancedChecks")
            info = import_module(".info", lens_package)
            self._lenses.append((basic_checks, advanced_checks, info))

    def investigate(self, request, client_ip):
        """
        This function will be called for every packet sent to the server.
        It will identify if the packet contains any kind of attack the WAF can protect from
        :param request: the user's request
        :param client_ip: the client ip address
        :type request: mitmproxy.http.HTTPFlow.request
        :type client_ip: ip
        :return: True if an attack was detected, otherwise, False
        :rtype: boolean
        """
        content = self._parse_request_content(request)
        if content is not None:
            for lens in self._lenses:
                attack_risks_findings, attack_info = self._magnifying_glass.detect(content, lens)
                found_risk = any(amount_of_risks > 0 for amount_of_risks in attack_risks_findings[toolbox.RiskLevels.NEGLIGIBLE:])
                if found_risk:
                    self._attacks_logger.add_attack_attempt(client_ip, content, attack_risks_findings)
                    if self._is_malicious_request(attack_risks_findings) or \
                            self._attacks_logger.is_continuity_attacks_in_continuity(client_ip):
                        self._assistant.set_findings(attack_risks_findings)
                        self._assistant.set_info(lens[self.INFO_INDEX].category, attack_info)
                        return True
        return False

    def _parse_request_content(self, request):
        """
        This function will check which type of request is
        the given request and it will return its content
        :param request: the user's request
        :type request: mitmproxy.http.HTTPFlow.request
        :return: the content of the request if any, otherwise, None
        :rtype: string or None
        """
        if request.method == "GET":
            return unquote_plus(request.data.path.decode().lower())
        elif request.method == "POST":
            request_content = ""
            for content in request.urlencoded_form.values():
                request_content += str(content) + " "
            return request_content.lower().replace('\n', "")
        return None

    def _is_malicious_request(self, findings):
        """
        This function will decide if the request is dangerous according to the findings
        :param findings: the risk levels the detector have found
        :type findings: list
        :return: True if the request is dangerous, otherwise, False
        :rtype: boolean
        """
        impact_level = 0
        for risk_occurrences, multiplying_factor in zip(findings[toolbox.RiskLevels.NEGLIGIBLE:], self._multiplying_factors):
            impact_level += risk_occurrences * multiplying_factor
        return impact_level >= 1
