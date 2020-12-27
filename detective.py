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
    _general_attack_info = []
    _deep_attack_info = []
    _links_attack = []
    _risks_found = [0] * len(RiskLevel)

    def __int__(self):
        """
        function initialize the variables in the detective class
        """
        plt.rcdefaults()
        self._detectors_list.append(sqlinjection_detector.Detector)
        self._detectors_list.append(xxe_detector.Detector)

    def detect(self, request):
        """
        This function will be called for every packet sent to the server.
        It will search for any kind of attack the WAF can protect from
        :param request: the user's request
        :type request: string
        :return: the information detected by the detector, empty string if no attack was detected
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
        objects = tuple([riskLevel for riskLevel in RiskLevel])
        y_pos = np.arange(len(objects))
        plt.bar(y_pos, self._risks_found, align='center', alpha=0.5)
        plt.xticks(y_pos, objects)
        plt.ylabel('Risks Found')
        plt.xlabel('Risks Levels')
        plt.title('Risks Found In The Last Day')
        plt.savefig('risks_graph.png')
