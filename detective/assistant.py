from time import sleep
from datetime import datetime
from threading import Thread
from importlib import import_module
import detective.lenses as lenses
from detective.risk_levels import RiskLevels
from log_related.email_sender import EmailSender
from log_related.log_composer import LogComposer
from log_related.graph_handler import GraphHandler

SECONDS_IN_DAY = 86400
TIME_TO_SEND_LOG = 5


class Assistant:
    _risks_findings = [0] * len(RiskLevels)
    _info = {}
    _general_info = {}
    _links = {}

    def __init__(self):
        thread = Thread(target=self._report_log)
        thread.daemon = True
        thread.start()

        for lens in lenses.__all__:
            lens_info = import_module(f"detective.lenses.{lens}.info")
            self._general_info[lens_info.category] = lens_info.general_info
            self._links[lens_info.category] = lens_info.links_for_info

    def set_findings(self, attack_risks_findings):
        """
        This function will gather all the findings from the malicious request
        :param attack_risks_findings: the risk findings about the identified attack
        :type attack_risks_findings: list
        """
        self._risk_findings = list(map(lambda new_finding, existing_finding: new_finding + existing_finding, attack_risks_findings, self._risk_findings))

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
            now = datetime.now()
            time_to_sleep = SECONDS_IN_DAY - round((now - now.replace(hour=0, minute=0, second=0, microsecond=0)).total_seconds()) - TIME_TO_SEND_LOG
            with open("f.txt", 'a') as f:
                f.write(str(time_to_sleep))
                sleep(time_to_sleep)
                f.write("yes")
                f.close()
            email_sender = EmailSender()
            log_composer = LogComposer()
            graph_handler = GraphHandler()
            graph_handler.create_graph(self._risks_findings)
            log_composer.write_log(self._pop_info())
            email_sender.send_log()
