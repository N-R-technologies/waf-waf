import os
import toml
from datetime import datetime


class DataManager:
    BLACKLIST_FILE_PATH = "waf_data/blacklist.toml"
    SERVER_INFO_FILE_PATH = "waf_data/server_info.toml"
    WRONG_DIAGNOSIS_FILE_PATH = "waf_data/wrong_diagnosis.waf_waf"
    WARNING_MESSAGE_FILE_PATH = "waf_data/warning_message.txt"
    WAF_DIAGNOSIS_HASH = "a7ac7ea7c7af02759b404c0ccd188045"

    _warning_msg_format = ""

    def __init__(self):
        with open(self.WARNING_MESSAGE_FILE_PATH, 'r') as warning_msg_file:
            self._warning_msg_format = warning_msg_file.read()
            warning_msg_file.close()

    def load_blacklist_configuration(self):
        if not os.path.exists(self.BLACKLIST_FILE_PATH):
            open(self.BLACKLIST_FILE_PATH, 'w').close()
        return set(toml.load(self.BLACKLIST_FILE_PATH).get("blacklist", []))

    def add_client_to_blacklist(self, attacker_ip_address, blacklist):
        blacklist.add(attacker_ip_address)
        with open(self.BLACKLIST_FILE_PATH, 'w') as blacklist_file:
            toml.dump({"blacklist": blacklist}, blacklist_file)
            blacklist_file.close()

    def is_wrong_diagnosis_request(self, request):
        return request.method == "POST" and self.WAF_DIAGNOSIS_HASH in request.urlencoded_form.keys()

    def add_client_to_wrong_diagnosis(self, client_ip_address):
        current_date = datetime.now().strftime("%d_%m_%Y__%H_%M_%S")
        if "ffff:" in client_ip_address and len(client_ip_address) > 5:
            client_ip_address = client_ip_address[client_ip_address.find("ffff:") + 5:]
        with open(self.WRONG_DIAGNOSIS_FILE_PATH, 'a') as wrong_diagnosis_file:
            wrong_diagnosis_file.write(f"{client_ip_address},{current_date}\n")
            wrong_diagnosis_file.close()

    def get_warning_message(self, attempts_left, max_attack_attempts, referer):
        warning_msg = self._warning_msg_format.replace("{referer}", referer)
        warning_msg = warning_msg.replace("{attempts_left}", str(max_attack_attempts + 1 - attempts_left))
        return warning_msg

    def write_server_info_configuration(self, first_request):
        with open(self.SERVER_INFO_FILE_PATH, 'w') as server_info_file:
            toml.dump({"host": first_request.host_header}, server_info_file)
            server_info_file.close()
