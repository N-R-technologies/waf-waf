from time import sleep
from datetime import datetime
from threading import Thread
from importlib import import_module
import detective.toolbox.lenses as lenses
from detective.toolbox.risk_levels import RiskLevels
import log_related


class Assistant:
    _info = {}
    _general_info = {}
    _links = {}
    _risks_findings = [0] * len(RiskLevels)
    email_sender = log_related.EmailSender()
    log_composer = log_related.LogComposer()
    graph_handler = log_related.GraphHandler()

    def __init__(self):
        thread = Thread(target=self._report_log)
        thread.daemon = True
        thread.start()

        for lens in lenses.__all__:
            lens_info = import_module(f"detective.toolbox.lenses.{lens}.info")
            self._general_info[lens_info.category] = lens_info.general_info
            self._links[lens_info.category] = lens_info.links_for_info

    def set_findings(self, attack_risks_findings):
        """
        This function will gather all the findings from the malicious request
        :param attack_risks_findings: the risk findings about the identified attack
        :type attack_risks_findings: list
        """
        self._risks_findings = list(map(lambda new_finding, existing_finding: new_finding + existing_finding, attack_risks_findings, self._risks_findings))

    def set_info(self, category, attack_info):
        """
        This function will gather all the information from the malicious request
        :param attack_info: the information about the identified attack
        :param category: the detector type
        :type attack_info: list
        :type category: string
        """
        if category not in self._info:
            self._info[category] = {
                "general": self._general_info[category],
                "attacks": set(attack_info),
                "links": self._links[category]
            }
        else:
            for attack_detected in attack_info:
                self._info[category]["attacks"].add(attack_detected)

    def _pop_info(self):
        """
        This function will gather all the information from the packet
        and will return the conclusions of it. then it will reset it
        :return: the conclusions of the detected attack's information
        :rtype: dict
        """
        summarized_info = {}
        for attack_name, attack_info in self._info.items():
            detected_risks = "Detected risks:\n" + "".join(attack_info["attacks"])
            summarized_info[attack_name] = f'{attack_info["general"]}\n{detected_risks}\n{attack_info["links"]}'
        self._info = {}
        return summarized_info

    def _report_log(self):
        """
        This function will report the log to the user every day
        """
        while True:
            current_time = datetime.now()
            report_time = current_time.replace(hour=23, minute=59, second=55)
            seconds_until_tomorrow = abs(round((report_time - current_time).total_seconds()))
            sleep(seconds_until_tomorrow)
            self.graph_handler.create_graph(self._risks_findings)
            self.log_composer.write_log(self._pop_info())
            self.email_sender.send_log()
            sleep(5)
