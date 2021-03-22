import sched
import time
from threading import Thread
from importlib import import_module
from detective.toolbox import lenses
from detective.toolbox.risk_levels import RiskLevels
import logger


class Assistant:
    _risks_findings = [0] * len(RiskLevels)
    _info = {}
    _general_info = {}
    _links = {}
    _email_sender = logger.EmailSender()
    _log_composer = logger.LogComposer()
    _graph_handler = logger.GraphHandler()
    SECONDS_IN_DAY = 86400

    def __init__(self):
        thread = Thread(target=self._start_send_emails_scheduler, args=(self.SECONDS_IN_DAY, ), daemon=True)
        thread.start()

        for lens in lenses.__all__:
            lens_info = import_module(f"detective.toolbox.lenses.{lens}.info")
            self._general_info[lens_info.category] = lens_info.general_info
            self._links[lens_info.category] = lens_info.links_for_info

    def _start_send_emails_scheduler(self, time_until_send):
        while True:
            scheduler = sched.scheduler(time.time, time.sleep)
            scheduler.enter(time_until_send, 1, self._report_log)
            scheduler.run()

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

    def _get_info(self):
        """
        This function will gather all the information from the
        received requests today and will return the conclusions of it
        :return: the conclusions of the detected attacks information
        :rtype: dict
        """
        summarized_info = {}
        for attack_name, attack_info in self._info.items():
            detected_risks = "Detected risks:\n" + "".join(attack_info["attacks"])
            summarized_info[attack_name] = f'{attack_info["general"]}\n{detected_risks}\n{attack_info["links"]}'
        return summarized_info

    def _reset(self):
        """
        This function will reset all the information about
        today's detected malicious requests
        """
        self._risks_findings = [0] * len(RiskLevels)
        self._info = {}

    def _report_log(self):
        """
        This function will report the log to
        the user at the end of every day
        """
        while True:
            self._graph_handler.create_graph(self._risks_findings)
            self._log_composer.write_log(self._get_info())
            self._email_sender.send_log()
            self._reset()
            time.sleep(5)
