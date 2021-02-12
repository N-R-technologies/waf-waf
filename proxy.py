import toml
import os
from mitmproxy import proxy, options, http
from mitmproxy.tools.dump import DumpMaster
from detective import Detective
from detective.toolbox.brute_force import detector

PROXY_LISTEN_HOST = "127.0.0.1"
PROXY_LISTEN_PORT = 8080


class WAF:
    BLACKLIST_FILE_PATH = "blacklist.toml"
    SERVER_INFO_FILE_PATH = "server_info.toml"

    _detective = Detective()
    _brute_force_detector = detector.BruteForceDetector()
    _blacklist = set()
    _is_first_request = True

    def __init__(self):
        self._load_blacklist_configuration(self.BLACKLIST_FILE_PATH)

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
        """
        This function will check and handle received malicious requests
        :param flow: The user's request
        :type flow: http.HTTPFlow
        :return: None
        """
        if self._is_first_request:
            self._write_server_info_configuration(flow.request, self.SERVER_INFO_FILE_PATH)
            self._is_first_request = False
        client_ip_address = flow.client_conn.ip_address[0]
        is_client_blocked = client_ip_address in self._blacklist
        if (is_client_blocked and flow.killable) or (self._brute_force_detector.is_request_blocked(flow.request)):
            flow.kill()
        else:
            self._brute_force_detector.count_user_requests(flow.request, flow.client_conn.ip_address[0])
            if self._detective.investigate(flow.request):
                if flow.killable:
                    flow.kill()
                self._add_client_to_blacklist(client_ip_address)

    def response(self, flow: http.HTTPFlow) -> None:
        self._brute_force_detector.add_delay(flow.response, flow.client_conn.ip_address[0])


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
