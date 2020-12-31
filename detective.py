import os
from importlib import import_module
from secretary import Secretary
from risk_level import RiskLevel


class Detective:
    _detectors = []
    _info = {}
    _secretary = Secretary()

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
                        self._set_info(attack_info)
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

    def _set_info(self, attack_info):
        """
        This function will gather all the information from the malicious request
        :param attack_info: the information about the identified attack
        :type attack_info: list
        """
        if attack_info[0] not in self._general_attack_info:
            self._general_attack_info.append(attack_info[0])
            self._deep_attack_info.append(attack_info[1])
            self._links_attack.append(attack_info[2])
        else:
            self._deep_attack_info[self._general_attack_info.index(attack_info[0])] += attack_info[1]

    def pop_info(self):
        """
        This function will gather all the information from the packet
        and will return the conclusions of it. then it will reset it
        :return: the conclusions of the given information
        :rtype: string
        """
        summarized_info = ""
        for general_info, deep_info, links in self._general_attack_info, self._deep_attack_info, self._links_attack:
            summarized_info += general_info + '\n' + deep_info + '\n' + links + '\n'
        self._reset_info()
        return summarized_info

    def _reset_info(self):
        self._general_attack_info = []
        self._deep_attack_info = []
        self._links_attack = []
