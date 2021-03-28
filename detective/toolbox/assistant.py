import time
import sched
from threading import Thread
from importlib import import_module
from detective.toolbox import lenses
from detective.toolbox import RiskLevels
import logger


class Assistant:
    SECONDS_IN_DAY = 86400

    _risks_findings = [0] * len(RiskLevels)
    _info = {}
    _general_info = {}
    _links = {}
    _email_sender = logger.EmailSender()
    _log_composer = logger.LogComposer()
    _graph_handler = logger.GraphHandler()

    def __init__(self):
        daily_log = Thread(target=self._start_daily_log_scheduler, daemon=True)
        daily_log.start()

        for lens in lenses.__all__:
            lens_info = import_module(f"detective.toolbox.lenses.{lens}.info")
            self._general_info[lens_info.category] = lens_info.general_info
            self._links[lens_info.category] = lens_info.links_for_info

    def set_findings(self, attack_risks_findings):
        self._risks_findings = list(map(lambda new_finding, existing_finding: new_finding + existing_finding, attack_risks_findings, self._risks_findings))

    def set_info(self, category, attack_info):
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
        summarized_info = {}
        for attack_name, attack_info in self._info.items():
            detected_risks = "Detected risks:\n" + "".join(attack_info["attacks"])
            summarized_info[attack_name] = f'{attack_info["general"]}\n{detected_risks}\n{attack_info["links"]}'
        return summarized_info

    def _reset(self):
        self._risks_findings = [0] * len(RiskLevels)
        self._info = {}

    def _start_daily_log_scheduler(self):
        while True:
            scheduler = sched.scheduler(time.time, time.sleep)
            scheduler.enter(self.SECONDS_IN_DAY, 1, self._report_log)
            scheduler.run()

    def _report_log(self):
        self._graph_handler.create_graph(self._risks_findings[RiskLevels.NEGLIGIBLE:])
        self._log_composer.write_log(self._get_info())
        self._email_sender.send_log()
        self._reset()
