import numpy as np
import matplotlib.pyplot as plt
import sqlinjection_detector
import xxe_detector
from risk_level import RiskLevel

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
    _risks_found = [0] * len(RiskLevel)
    _general_attack_info = []
    _deep_attack_info = []
    _links_attack = []

    def __int__(self):
        plt.rcdefaults()
        self._detectors_list.append(sqlinjection_detector.Detector)
        self._detectors_list.append(xxe_detector.Detector)

    def detect(self, request):
        """
        This function will be called for every packet sent to the server.
        It will identify if the packet contains any kind of attack the WAF can protect from
        :param request: the user's request
        :type request: string
        :return: True if an attack was detected, otherwise, False
        :rtype: boolean
        """
        for detector in self._detectors_list:
            attack_info, attack_risks_findings = detector.detect(request)
            if any(risk > RiskLevel.NO_RISK for risk in attack_risks_findings[1:]):
                total_risk_level = 0
                for i in range(1, len(attack_risks_findings[1:])):
                    total_risk_level += i * attack_risks_findings[i]
                amount_of_risks = sum(attack_risks_findings[1:])
                avg_risk_level = total_risk_level / amount_of_risks
                if avg_risk_level > RiskLevel.LARGE_RISK:
                    self._set_info(attack_info)
                    self._set_graph(attack_risks_findings)
                    return True
        return False

    def _set_info(self, attack_info):
        """
        This function will gather all the information from the packet
        :param attack_info: the information about the identified attack
        :type attack_info: list
        """
        if attack_info[0] not in self._general_attack_info:
            self._general_attack_info.append(attack_info[0])
            self._deep_attack_info.append(attack_info[1])
            self._links_attack.append(attack_info[2])
        else:
            self._deep_attack_info[self._general_attack_info.index(attack_info[0])] += attack_info[1]

    def _set_graph(self, attack_risks_findings):
        """
        This function will add the current attack risks findings values to the
        total detective's risks findings
        :param attack_risks_findings: the risk levels of the identified attack
        :type attack_risks_findings: list
        """
        for risk_found_day, risk_found_request in self._risks_found[1:], attack_risks_findings[1:]:
            risk_found_day += risk_found_request

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
        self._general_attack_info = []
        self._deep_attack_info = []
        self._links_attack = []

    def create_graph(self):
        """
        This function will create an image graph based on the detectors findings
        """
        objects = tuple([risk_level for risk_level in RiskLevel])
        y_pos = np.arange(len(objects))
        plt.bar(y_pos, self._risks_found, align='center', alpha=0.5)
        plt.xticks(y_pos, objects)
        plt.ylabel('Risks Found')
        plt.xlabel('Risks Levels')
        plt.title('Risks Found In The Last Day')
        plt.savefig('risks_graph.png')
