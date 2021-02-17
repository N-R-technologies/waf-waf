import os
import sched
import toml
from time import time, sleep
from threading import Thread, Lock
from datetime import date


class AttacksLogger:
    ATTACKS_LOG_FILE_PATH = "detective/attacks_logger/attacks.toml"
    SECONDS_IN_WEEK = 604800

    def __init__(self):
        self._attacks_log_lock = Lock()
        self._attacks_statistics_lock = Lock()
        self._attacks_statistics = dict()
        open(self.ATTACKS_LOG_FILE_PATH, 'r').close()
        clear_attacks_log = Thread(target=self._schedule_clear_attacks_log)
        clear_attacks_log.start()

    def add_attack_attempt(self, attacker_ip, attack_content, risks_level):
        for risk_level in risks_level:
            if risk_level < 1:
                with self._attacks_statistics_lock:
                    if attacker_ip in self._attacks_statistics.keys():
                        self._attacks_statistics[attacker_ip] += risk_level
                    else:
                        self._attacks_statistics[attacker_ip] = risk_level
            if not os.path.exists(self.ATTACKS_LOG_FILE_PATH):
                with self._attacks_log_lock:
                    open(self.ATTACKS_LOG_FILE_PATH, 'w').close()
            with self._attacks_log_lock:
                attacks = list(toml.load(self.ATTACKS_LOG_FILE_PATH).get(date.today().strftime("%d/%m/%Y"), []))
            attacks.append((attacker_ip, attack_content))
            with self._attacks_log_lock:
                toml.dump({date.today().strftime("%d/%m/%Y"): [(attacker_ip, attack_content)]}, self.ATTACKS_LOG_FILE_PATH)

    def get_attack(self, search_attacker_ip, search_attack_date):
        with self._attacks_log_lock:
            attacks_dict = dict(toml.load(self.ATTACKS_LOG_FILE_PATH).get(search_attack_date, []))
        for attacker_ip, attack_content in attacks_dict.items():
            if attacker_ip == search_attacker_ip:
                return attack_content
        return None

    def is_continuity_attacks_in_continuity(self, attacker_ip):
        with self._attacks_statistics_lock:
            if self._attacks_statistics[attacker_ip] >= 1:
                self._attacks_statistics[attacker_ip] = 0
                return True
        return False

    def _clear_log(self):
        with self._attacks_log_lock:
            open(self.ATTACKS_LOG_FILE_PATH, 'w').close()

    def _schedule_clear_attacks_log(self):
        while True:
            scheduler = sched.scheduler(time, sleep)
            scheduler.enter(self.SECONDS_IN_WEEK, 1, self._clear_log)
            scheduler.run()
