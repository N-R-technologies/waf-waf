from importlib import import_module
import lenses
from magnifying_glass import MagnifyingGlass
from assistant import Assistant
from risk_levels import RiskLevels

INFO_INDEX = 2


class Detective:
    _lenses = []
    _magnifying_glass = MagnifyingGlass()
    _assistant = Assistant()

    def __init__(self):
        for lens in lenses.__all__:
            lens_package = f"lenses.{lens}"
            basic_checks = import_module(".basic_checks", lens_package).BasicChecks
            advanced_checks = import_module(".advanced_checks", lens_package).AdvancedChecks
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
        request_content = self._parse_request_content(request)
        if request_content is not None:
            for lens in self._lenses:
                attack_risks_findings, attack_info = self._magnifying_glass.detect(request_content, lens)
                found_risk = any(amount_of_risks > 0 for amount_of_risks in attack_risks_findings[RiskLevels.NEGLIGIBLE:])
                if found_risk:
                    if self._is_malicious_request(attack_risks_findings):
                        self._assistant.set_info(lens[INFO_INDEX].category, attack_info)
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
            return request.data.path.decode().lower().replace('\n', "")
        elif request.method == "POST":
            return request.content.decode().lower().replace('\n', "")
        return None

    def _is_malicious_request(self, risks_findings):
        """
        This function will decide if the request is dangerous according to its impact
        :param risks_findings: the risk levels the detector have found
        :type risks_findings: list
        :return: True if the request is dangerous, otherwise, False
        :rtype: boolean
        """
        total_risk_levels = len(RiskLevels) - 1
        impact_level = 0
        for risk_occurrences, risk_level in zip(risks_findings[RiskLevels.NEGLIGIBLE:],
                                                range(RiskLevels.NEGLIGIBLE, RiskLevels.CRITICAL)):
            multiplying_factor = risk_level / total_risk_levels
            impact_level += multiplying_factor * risk_occurrences
        is_impact_high = any(risk_occurrences > 0 for risk_occurrences in risks_findings[RiskLevels.CRITICAL:])
        return is_impact_high or impact_level >= 1
