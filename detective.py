import os
from importlib import import_module
from assistant import Assistant
from risk_level import RiskLevel


class Detective:
    _detectors = []
    _assistant = Assistant()

    def __init__(self):
        for detector_type in os.listdir("detectors"):
            self._detectors.append(import_module("detectors." + detector_type + ".detector").Detector)
    
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
            for detector in self._detectors:
                attack_info, attack_risks_findings = detector.detect(request_content)
                found_risk = any(risk_level_amount > 0 for risk_level_amount in attack_risks_findings[RiskLevel.Negligble:])
                if found_risk:
                    if self._is_dangerous_request(attack_risks_findings):
                        self._assistant.set_info(detector.category, attack_info)
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

    def _is_dangerous_request(self, risks_findings):
        """
        This function will decide if the request is dangerous according to its impact
        :param risks_findings: the risk levels the detector have found
        :type risks_findings: list
        :return: True if the request is dangerous, otherwise, False
        :rtype: boolean
        """
        amount_of_risks = len(RiskLevel) - 1
        total_impact_level = 0
        for risk_occurrences, i in zip(risks_findings[RiskLevel.Negligble:],
                                       range(RiskLevel.Negligble, RiskLevel.Critical)):
            multiplying_factor = i / amount_of_risks
            total_impact_level += multiplying_factor * risk_occurrences
        is_impact_high = any(risk_occurrences > 0 for risk_occurrences in risks_findings[RiskLevel.Critical:])
        return is_impact_high or total_impact_level >= 1
