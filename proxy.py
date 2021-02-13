import os
from datetime import date
import toml
from mitmproxy import proxy, options, http
from mitmproxy.tools.dump import DumpMaster
from detective import Detective

PROXY_LISTEN_HOST = "127.0.0.1"
PROXY_LISTEN_PORT = 8080


class WAF:
    BLACKLIST_FILE_PATH = "blacklist.toml"
    SERVER_INFO_FILE_PATH = "server_info.toml"
    WRONG_DIAGNOSIS_FILE_PATH = "wrong_diagnosis.toml"
    WARNING_MESSAGE_FILE_PATH = "warning_message.txt"
    MAX_ATTACK_ATTEMPTS = 2

    _detective = Detective()
    _blacklist = set()
    _is_first_request = True

    def __init__(self):
        self._load_blacklist_configuration(self.BLACKLIST_FILE_PATH)
        self._attack_attempts = dict()
        with open(self.WARNING_MESSAGE_FILE_PATH, "r") as warning_msg_file:
            self._warning_msg_format = warning_msg_file.read()
            warning_msg_file.close()

    def _get_warning_message(self, client_ip_address, referer):
        warning_msg = self._warning_msg_format.replace("{referer}", referer)
        warning_msg = warning_msg.replace("{attempts_left}", str(self.MAX_ATTACK_ATTEMPTS + 1 - self._attack_attempts[client_ip_address]))
        return warning_msg

    def _add_ip_to_wrong_diagnosis_file(self, ip):
        current_date = date.today().strftime("%d/%m/%Y")
        with open(self.WRONG_DIAGNOSIS_FILE_PATH, 'a') as wrong_diagnosis_file:
            toml.dump({ip: current_date}, wrong_diagnosis_file)
            wrong_diagnosis_file.close()

    def _is_wrong_diagnosis_request(self, request):
        # a7ac7ea7c7af02759b404c0ccd188045 = WAF diagnosis in MD5 hash
        return request.method == "POST" and "a7ac7ea7c7af02759b404c0ccd188045" in request.urlencoded_form.keys()

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

    def request(self, flow: http.HTTPFlow) -> None:
        if self._is_first_request:
            self._write_server_info_configuration(flow.request, self.SERVER_INFO_FILE_PATH)
            self._is_first_request = False
        client_ip_address = flow.client_conn.ip_address[0]
        is_client_blocked = client_ip_address in self._blacklist
        if is_client_blocked and flow.killable:
            flow.kill()
        elif self._is_wrong_diagnosis_request(flow.request):
            self._add_ip_to_wrong_diagnosis_file(client_ip_address)
        else:
            if self._detective.investigate(flow.request):
                if client_ip_address in self._attack_attempts.keys() and self._attack_attempts[client_ip_address] >= self.MAX_ATTACK_ATTEMPTS:
                    if flow.killable:
                        flow.kill()
                    self._add_client_to_blacklist(client_ip_address)
                else:
                    flow.request.headers["Host"] = "No such host"
                    if client_ip_address not in self._attack_attempts.keys():
                        self._attack_attempts[client_ip_address] = 1
                    else:
                        self._attack_attempts[client_ip_address] += 1
                    referer = flow.request.headers["Referer"]
                    flow.response = http.HTTPResponse.make(
                        400,
                        self._get_warning_message(client_ip_address, referer),
                        {"content-type": "text/html"},
                    )


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
