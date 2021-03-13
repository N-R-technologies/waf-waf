from time import time, sleep
from datetime import datetime
from threading import Thread, Lock
import sched


class AttacksLogger:
    ATTACKS_LOG_FILE_PATH = "detective/attacks_logger/attacks.waf_waf"
    SECONDS_IN_WEEK = 604800

    _attacks_statistics = dict()
    _attacks_log_lock = Lock()
    _attacks_statistics_lock = Lock()

    def __init__(self):
        open(self.ATTACKS_LOG_FILE_PATH, 'w').close()
        clear_attacks_log = Thread(target=self._schedule_clear_attacks_log)
        clear_attacks_log.start()

    def add_attack_attempt(self, attacker_ip, attack_content, risks_level):
        current_date = datetime.now().strftime("%d_%m_%Y__%H_%M_%S")
        with open(self.ATTACKS_LOG_FILE_PATH, "a") as attacks_log_file:
            attacks_log_file.write(f"{attacker_ip},{current_date},{attack_content}\n")
            attacks_log_file.close()
        for risk_level in risks_level:
            if risk_level < 1:
                with self._attacks_statistics_lock:
                    if attacker_ip in self._attacks_statistics.keys():
                        self._attacks_statistics[attacker_ip] += risk_level
                    else:
                        self._attacks_statistics[attacker_ip] = risk_level

    def is_continuity_attacks_in_continuity(self, attacker_ip):
        with self._attacks_statistics_lock:
            if attacker_ip in self._attacks_statistics.keys() and self._attacks_statistics[attacker_ip] >= 1:
                self._attacks_statistics[attacker_ip] = 0
                return True
        return False

    def _schedule_clear_attacks_log(self):
        while True:
            scheduler = sched.scheduler(time, sleep)
            scheduler.enter(self.SECONDS_IN_WEEK, 1, self._clear_log)
            scheduler.run()
    
    def _clear_log(self):
        with self._attacks_log_lock:
            open(self.ATTACKS_LOG_FILE_PATH, 'w').close()
