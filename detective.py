import sqlinjection_detector
import xxe_detector
from risk_level import RiskLevel
from graph_handler import GraphHandler

"""
flow of the program - every packet will pass throw the detect function
then the detect function will return True if it detect any risks in the packet, if so, the proxy
will block the packet, and add the sender ip to the blacklist, otherwise, the packer will send to
the server as usual. every day (24 hours), the main program will call to the function create graph, that will
create a graph that will create graph according all the findings in the last 24 hours. after that
the main function will call to the get info function, that will
gather all the information found together, and then reset the information. at the end, the main
program will call to the makeLog + sendEmail functions that will create the daily log file and send it to the user 
"""


class Detective:
    _detectors_list = []
    _general_attack_info = []
    _deep_attack_info = []
    _links_attack = []

    def __init__(self):
        self._detectors_list.append(sqlinjection_detector.Detector)
        self._detectors_list.append(xxe_detector.Detector)

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
        if request_content != "":
            for detector in self._detectors_list:
                attack_info, attack_risks_findings = detector.detect(request_content)
                if any(risk > RiskLevel.NO_RISK for risk in attack_risks_findings[1:]):
                    total_risk_level = 0
                    for i in range(1, len(attack_risks_findings[1:])):
                        total_risk_level += i * attack_risks_findings[i]
                    amount_of_risks = sum(attack_risks_findings[1:])
                    avg_risk_level = total_risk_level / amount_of_risks
                    if avg_risk_level >= RiskLevel.MEDIUM_RISK:
                        self._set_info(attack_info)
                        GraphHandler.set_graph(attack_risks_findings)
                        return True
        return False

    def _analyze_request(self, request):
        """
        This function will check which type of request is
        the given request and it will return its content
        :param request: the user's request
        :type request: mitmproxy.http.HTTPFlow.request
        :return: the content of the request
        :rtype: string
        """
        content = ""
        if request.method == "GET":
            content = request.data.path.decode()
        elif request.method == "POST":
            content = request.content.decode()
        return content.replace('\n', "").lower()

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

    def get_info(self):
        """
        This function will gather all the information from the packet
        and will return the conclusions of it
        :return: the conclusions of the given information
        :rtype: string
        """
        summarized_info = ""
        for general_info, deep_info, links in self._general_attack_info, self._deep_attack_info, self._links_attack:
            summarized_info += general_info + '\n' + deep_info + '\n' + links + '\n'
        self._reset_info()
        return summarized_info

    def _reset_info(self):
        GraphHandler.reset_findings()
        self._general_attack_info = []
        self._deep_attack_info = []
        self._links_attack = []
