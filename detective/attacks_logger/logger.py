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
        open(self.ATTACKS_LOG_FILE_PATH, 'w').close()
        clear_attacks_log = Thread(target=self._schedule_clear_attacks_log)
        clear_attacks_log.start()

    def add_attack_attempt(self, attacker_ip, attack_content, risks_level):
        current_date = date.today().strftime("%d_%m_%Y")

        if toml.load(self.ATTACKS_LOG_FILE_PATH).get(current_date, None) is None:
            with open(self.ATTACKS_LOG_FILE_PATH, 'a') as attacks_file:
                with self._attacks_log_lock:
                    toml.dump(toml.loads(f'[{current_date}]'), attacks_file)
                attacks_file.close()
        with self._attacks_log_lock:
            attacks = toml.load(self.ATTACKS_LOG_FILE_PATH)
        if attacker_ip in attacks[current_date].keys():
            attacks[current_date][attacker_ip].append(attack_content)
        else:
            attacks[current_date][attacker_ip] = [attack_content]
        with self._attacks_log_lock:
            with open(self.ATTACKS_LOG_FILE_PATH, 'w') as attacks_file:
                toml.dump(attacks, attacks_file)
        attacks_file.close()
        for risk_level in risks_level:
            if risk_level < 1:
                with self._attacks_statistics_lock:
                    if attacker_ip in self._attacks_statistics.keys():
                        self._attacks_statistics[attacker_ip] += risk_level
                    else:
                        self._attacks_statistics[attacker_ip] = risk_level

    def get_attack(self, search_attacker_ip, search_attack_date):
        attacks = {}
        with self._attacks_log_lock:
            attacks = toml.load(self.ATTACKS_LOG_FILE_PATH).get(search_attack_date, {})
        if search_attacker_ip in attacks.keys():
            return attacks[search_attacker_ip]
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