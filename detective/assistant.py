import os
from importlib import import_module


class Assistant:
    _info = {}
    _general_info = {}
    _links = {}

    def __init__(self):
        for detector_type in os.listdir("detector_types"):
            detector_info = import_module("detector_types." + detector_type + ".info")
            self._general_info[detector_info.category] = detector_info.general_info
            self._links[detector_info.category] = detector_info.links_for_info

    def set_info(self, category, attack_info):
        """
        This function will gather all the information from the malicious request
        :param attack_info: the information about the identified attack
        :param category: the detector type
        :type attack_info: list
        :type category: string
        """
        if category not in self._info:
            self._info[category] = {}
            self._info[category]["general"] = self._general_info[category]
            self._info[category]["attacks"] = set(attack_info)
            self._info[category]["links"] = self._links[category]
        else:
            for attack_detected in attack_info:
                self._info[category]["attacks"].add(attack_detected)

    def pop_info(self):
        """
        This function will gather all the information from the packet
        and will return the conclusions of it. then it will reset it
        :return: the conclusions of the given information
        :rtype: string
        """
        summarized_info = ""
        for attack_detected in self._info:
            summarized_info += attack_detected["general"] + '\n' + \
                               '\n'.join(attack_detected["attacks"]) + attack_detected["links"]
        self._info = {}
        return summarized_info
