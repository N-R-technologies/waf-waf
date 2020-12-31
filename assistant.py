import sqlinjection_info
import xxe_info


class Assistant:
    _info = {}
    _general_info = {}
    _links = {}

    def __init__(self):
        self._general_info = {"SQL Injection": sqlinjection_info.general_info, "XXE": xxe_info.general_info}
        self._links = {"SQL Injection": sqlinjection_info.links_for_info, "XXE": xxe_info.links_for_info}

    def summarize_info(self, attack_info):
        pass

    def set_info(self, category, attack_info):
        """
        This function will gather all the information from the malicious request
        :param attack_info: the information about the identified attack
        :type attack_info: list
        """
        if category not in self._info:
            self._info[category]["General_info"] = self._general_info[category]

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

    def reset_info(self):
        GraphHandler.reset_findings()