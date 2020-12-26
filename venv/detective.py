import sqlinjection_detector
import xxe_detector
from risk_level import RiskLevel
import matplotlib.pyplot as plt
import numpy as np
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

plt.rcdefaults()


class Detective:
    _detectors_list = []
    _general_attack_info = []
    _deep_attack_info = []
    _links_attack = []
    _risks_found = [0] * len(RiskLevel)
    
    def __int__(self):
        """
        function initialize the variables in the detective class
        """
        self._detectors_list.append(sqlinjection_detector.Detector)
        self._detectors_list.append(xxe_detector.Detector)

    def detect(self, request):
        """
        function called for every packet sent to the server, and then
        search for any kind of attack the waf can detect
        :param request: the user's request
        :type request: string
        :return: the info detected by the detector, empty string if no attack was detected
        :rtype: string
        """
        for detector in self._detectors_list:
            attack_info, add_to_risk_graph = detector.detect(request)
            if not all(risk == 0 for risk in add_to_risk_graph[1:]):
                if attack_info[0] not in self._general_attack_info:
                    self._general_attack_info.append(attack_info[0])
                    self._deep_attack_info.append(attack_info[1])
                    self._links_attack.append(attack_info[2])
                else:
                    self._deep_attack_info[self._general_attack_info.index(attack_info[0])] += attack_info[1]
                for risk_found_request, risk_found_day in add_to_risk_graph[1:], self._risks_found[1:]:
                    risk_found_day += risk_found_request
                # need to add the functionality for checking if we should block the packet or not

    def get_info(self):
        """
        function gathering all the info from the packet and return the conclusion of it
        :return: all the info together
        :rtype: string
        """
        summarize_info = ""
        for general_info, deep_info, links in self._general_attack_info, self._deep_attack_info, self._links_attack:
            summarize_info += general_info + '\n' + deep_info + '\n' + links + '\n'
        self._detectors_list = []
        self._general_attack_info = []
        self._deep_attack_info = []
        self._links_attack = []
        self._risks_found = [0] * len(RiskLevel)
        return summarize_info

    def create_graph(self):
        """
        function create graph image based on the findings
        """
        objects = tuple([int(riskLevel) for riskLevel in RiskLevel])
        y_pos = np.arange(len(objects))
        plt.bar(y_pos, self._risks_found, align='center', alpha=0.5)
        plt.xticks(y_pos, objects)
        plt.ylabel('Risks Found')
        plt.xlabel('Risk Level')
        plt.title('Risk Founds In The Last Day')
        plt.savefig('risks_graph.png')

