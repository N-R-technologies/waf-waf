import os
import toml
from datetime import date


class AttacksLogger:
    ATTACKS_LOG_FILE_PATH = "attacks.toml"

    def __init__(self):
        open(self.ATTACKS_LOG_FILE_PATH, 'r').close()

    def add_attack_attempt(self, attacker_ip, attack_content):
        if not os.path.exists(self.ATTACKS_LOG_FILE_PATH):
            open(self.ATTACKS_LOG_FILE_PATH, 'w').close()
        attacks = list(toml.load(self.ATTACKS_LOG_FILE_PATH).get(date.today().strftime("%d/%m/%Y"), []))
        attacks.append((attacker_ip, attack_content))
        toml.dump({date.today().strftime("%d/%m/%Y"): [(attacker_ip, attack_content)]}, self.ATTACKS_LOG_FILE_PATH)

    def get_attack(self, attacker_ip, attack_date):
        return list(toml.load(self.ATTACKS_LOG_FILE_PATH).get(date.today().strftime("%d/%m/%Y"), []))

    def clear_log(self):
        open(self.ATTACKS_LOG_FILE_PATH, 'w').close()
