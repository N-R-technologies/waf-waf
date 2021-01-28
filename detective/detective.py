from importlib import import_module
from urllib.parse import unquote_plus
import detective.toolbox as toolbox


class Detective:
    NEGLIGIBLE = 1/5
    SLIGHT = 1/2
    MODERATE = 1/3
    CRITICAL = 1
    CATASTROPHIC = 1
    INFO_INDEX = 2

    _multiplying_factors = ()
    _lenses = []
    _magnifying_glass = toolbox.MagnifyingGlass()
    _assistant = toolbox.Assistant()

    def __init__(self):
        self._multiplying_factors = (self.NEGLIGIBLE, self.SLIGHT, self.MODERATE, self.CRITICAL, self.CATASTROPHIC)
        for lens in toolbox.lenses.__all__:
            lens_package = f"detective.toolbox.lenses.{lens}"
            basic_checks = getattr(import_module(".basic_checks", lens_package), "BasicChecks")
            advanced_checks = getattr(import_module(".advanced_checks", lens_package), "AdvancedChecks")
            info = import_module(".info", lens_package)
            self._lenses.append((basic_checks, advanced_checks, info))

    def investigate(self, request):
        """
        This function will be called for every packet sent to the server.
        It will identify if the packet contains any kind of attack the WAF can protect from
        :param request: the user's request
        :type request: mitmproxy.http.HTTPFlow.request
        :return: True if an attack was detected, otherwise, False
        :rtype: boolean
        """
        content = self._parse_request_content(request)
        if content is not None:
            for lens in self._lenses:
                attack_risks_findings, attack_info = self._magnifying_glass.detect(content, lens)
                found_risk = any(amount_of_risks > 0 for amount_of_risks in attack_risks_findings[toolbox.RiskLevels.NEGLIGIBLE:])
                if found_risk:
                    if self._is_malicious_request(attack_risks_findings):
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
            return request.content.decode().lower().replace('\n', "")
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
