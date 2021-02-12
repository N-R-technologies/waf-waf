import os
from datetime import date
import toml


class AttacksLogger:

    def __init__(self):
        open("attacks.toml", 'r').close()

    def add_attack_attempt_to_log(self, attack_content, attacker_ip):
        file_name = "attacks.toml"
        if not os.path.exists(file_name):
            open(file_name, 'w').close()
        attacks = list(toml.load(file_name).get(date.today().strftime("%d/%m/%Y"), []))
        attacks.append((attacker_ip, attack_content))
        toml.dump({date.today().strftime("%d/%m/%Y"): [(attacker_ip, attack_content)]}, file_name)

    def clear_log_file(self):
        open("attacks.toml", 'w').close()

    def get_specific_attack(self, date, ip) -> list:
        return list(toml.load("attacks.toml").get(date.today().strftime("%d/%m/%Y"), []))


