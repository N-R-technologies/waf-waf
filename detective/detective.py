import os
from importlib import import_module
from universal_detector import UniversalDetector
from assistant import Assistant
from risk_levels import RiskLevels

BASIC_CHECKS = 0
ADVANCED_CHECKS = 1
INFO = 2


class Detective:
    _detector_types = []
    _universal_detector = UniversalDetector()
    _assistant = Assistant()

    def __init__(self):
        for detector_type in os.listdir("detector_types"):
            detector_basic_checks = import_module("detector_types." + detector_type + ".basic_checks").BasicChecks
            detector_advanced_checks = import_module("detector_types." + detector_type + ".advanced_checks").AdvancedChecks
            detector_info = import_module("detector_types." + detector_type + ".info")
            self._detector_types.append((detector_basic_checks, detector_advanced_checks, detector_info))

    def detect(self, request):
        """
        This function will be called for every packet sent to the server.
        It will identify if the packet contains any kind of attack the WAF can protect from
        :param request: the user's request
        :type request: mitmproxy.http.HTTPFlow.request
        :return: True if an attack was detected, otherwise, False
        :rtype: boolean
        """
        request_content = self._analyze_request(request)
        if request_content is not None:
            for detector_type in self._detector_types:
                attack_risks_findings, attack_info = self._universal_detector.detect(
                                                     request_content, detector_type[BASIC_CHECKS],
                                                     detector_type[ADVANCED_CHECKS], detector_type[INFO])
                found_risk = any(amount_of_risks > 0 for amount_of_risks in attack_risks_findings[RiskLevels.NEGLIGIBLE:])
                if found_risk:
                    if self._is_malicious_request(attack_risks_findings):
                        self._assistant.set_info(detector_type[INFO].category, attack_info)
                        return True
        return False

    def _analyze_request(self, request):
        """
        This function will check which type of request is
        the given request and it will return its content
        :param request: the user's request
        :type request: mitmproxy.http.HTTPFlow.request
        :return: the content of the request if any, otherwise, None
        :rtype: string or None
        """
        if request.method == "GET":
            return request.data.path.decode()
        elif request.method == "POST":
            return request.content.decode()
        return None

    def _is_malicious_request(self, risks_findings):
        """
        This function will decide if the request is dangerous according to its impact
        :param risks_findings: the risk levels the detector have found
        :type risks_findings: list
        :return: True if the request is dangerous, otherwise, False
        :rtype: boolean
        """
        amount_of_risks = len(RiskLevels) - 1
        impact_level = 0
        for risk_occurrences, i in zip(risks_findings[RiskLevels.NEGLIGIBLE:],
                                       range(RiskLevels.NEGLIGIBLE, RiskLevels.CRITICAL)):
            multiplying_factor = i / amount_of_risks
            impact_level += multiplying_factor * risk_occurrences
        is_impact_high = any(risk_occurrences > 0 for risk_occurrences in risks_findings[RiskLevels.CRITICAL:])
        return is_impact_high or impact_level >= 1
