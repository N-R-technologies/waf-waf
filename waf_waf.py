import os
import toml
from datetime import datetime
from mitmproxy import proxy, options, http
from mitmproxy.tools.dump import DumpMaster
from detective import Detective
from detective.toolbox.brute_force import BruteForceDetector, CaptchaImplementer

PROXY_LISTEN_HOST = "127.0.0.1"
PROXY_LISTEN_PORT = 8080


class WAF:
    BLACKLIST_FILE_PATH = "waf_data/blacklist.toml"
    SERVER_INFO_FILE_PATH = "waf_data/server_info.toml"
    WRONG_DIAGNOSIS_FILE_PATH = "waf_data/wrong_diagnosis.waf_waf"
    WARNING_MESSAGE_FILE_PATH = "waf_data/warning_message.txt"
    WAF_DIAGNOSIS_HASH = "a7ac7ea7c7af02759b404c0ccd188045"
    MAX_ATTACK_ATTEMPTS = 2

    _detective = Detective()
    _brute_force_detector = BruteForceDetector()
    _captcha_implementer = CaptchaImplementer()
    _blacklist = set()
    _is_first_request = True

    def __init__(self):
        self._load_blacklist_configuration(self.BLACKLIST_FILE_PATH)
        self._attack_attempts = dict()
        with open(self.WARNING_MESSAGE_FILE_PATH, 'r') as warning_msg_file:
            self._warning_msg_format = warning_msg_file.read()
            warning_msg_file.close()

    def _load_blacklist_configuration(self, blacklist_file_path):
        if os.path.exists(blacklist_file_path):
            self._blacklist = set(toml.load(blacklist_file_path).get("blacklist", []))
        else:
            open(blacklist_file_path, 'w').close()

    def _write_server_info_configuration(self, first_request, server_info_file_path):
        with open(server_info_file_path, 'w') as server_info_file:
            toml.dump({"host": first_request.host_header}, server_info_file)
            server_info_file.close()

    def _add_client_to_blacklist(self, attacker_ip_address):
        self._blacklist.add(attacker_ip_address)
        with open(self.BLACKLIST_FILE_PATH, 'w') as blacklist_file:
            toml.dump({"blacklist": self._blacklist}, blacklist_file)
            blacklist_file.close()

    def _get_warning_message(self, client_ip_address, referer):
        warning_msg = self._warning_msg_format.replace("{referer}", referer)
        warning_msg = warning_msg.replace("{attempts_left}", str(self.MAX_ATTACK_ATTEMPTS + 1 - self._attack_attempts[client_ip_address]))
        return warning_msg

    def _is_wrong_diagnosis_request(self, request):
        return request.method == "POST" and self.WAF_DIAGNOSIS_HASH in request.urlencoded_form.keys()

    def _add_client_to_wrong_diagnosis(self, client_ip_address):
        current_date = datetime.now().strftime("%d_%m_%Y__%H_%M_%S")
        if "ffff:" in client_ip_address and len(client_ip_address) > 5:
            client_ip_address = client_ip_address[client_ip_address.find("ffff:")+5:]
        with open(self.WRONG_DIAGNOSIS_FILE_PATH, "a") as wrong_diagnosis_file:
            wrong_diagnosis_file.write(f"{client_ip_address},{current_date}\n")
            wrong_diagnosis_file.close()

    def request(self, flow: http.HTTPFlow) -> None:
        if self._is_first_request:
            self._write_server_info_configuration(flow.request, self.SERVER_INFO_FILE_PATH)
            self._is_first_request = False
        client_ip_address = flow.client_conn.ip_address[0]
        is_client_blocked = client_ip_address in self._blacklist
        if (is_client_blocked or self._brute_force_detector.is_request_blocked(flow.request, client_ip_address)) and flow.killable:
            flow.kill()
        elif self._is_wrong_diagnosis_request(flow.request):
            self._add_client_to_wrong_diagnosis(client_ip_address)
        else:
            self._brute_force_detector.count_user_requests(flow.request, client_ip_address)
            if self._detective.investigate(flow.request, client_ip_address):
                if client_ip_address in self._attack_attempts.keys() and self._attack_attempts[client_ip_address] >= self.MAX_ATTACK_ATTEMPTS:
                    if flow.killable:
                        flow.kill()
                    else:
                        flow.request.headers["Host"] = "No such host"
                        if client_ip_address in self._attack_attempts.keys():
                            self._attack_attempts[client_ip_address] += 1
                        else:
                            self._attack_attempts[client_ip_address] = 1
                        referer = flow.request.headers["Referer"]
                        flow.response = http.HTTPResponse.make(400, self._get_warning_message(client_ip_address, referer), {"content-type": "text/html"})
                        self._add_client_to_blacklist(client_ip_address)
                else:
                    flow.request.headers["Host"] = "No such host"
                    if client_ip_address in self._attack_attempts.keys():
                        self._attack_attempts[client_ip_address] += 1
                    else:
                        self._attack_attempts[client_ip_address] = 1
                    referer = flow.request.headers["Referer"]
                    flow.response = http.HTTPResponse.make(400, self._get_warning_message(client_ip_address, referer), {"content-type": "text/html"})

    def response(self, flow: http.HTTPFlow) -> None:
        user_ip_address = flow.client_conn.ip_address[0]
        self._brute_force_detector.add_delay(flow.response, user_ip_address)
        login_url = self._captcha_implementer.get_login_url(flow.request)
        if login_url is not None:
            if not self._captcha_implementer.has_login_permission(user_ip_address):
                captcha = self._captcha_implementer.implement(user_ip_address, login_url)
                if captcha is not None:
                    flow.response = http.HTTPResponse.make(200, captcha, {"content-type": "text/html"})
            else:
                self._captcha_implementer.remove_login_permission(user_ip_address)


addons = [
    WAF()
]

options = options.Options(listen_host=PROXY_LISTEN_HOST, listen_port=PROXY_LISTEN_PORT)
options.add_option("body_size_limit", int, 0, "")
options.add_option("intercept_active", bool, False, "")
options.add_option("keep_host_header", bool, True, "")
proxy_config = proxy.config.ProxyConfig(options)

proxy = DumpMaster(options)
proxy.server = proxy.server.ProxyServer(proxy_config)
proxy.addons.add(addons)

try:
    proxy.run()
except KeyboardInterrupt:
    proxy.shutdown()
