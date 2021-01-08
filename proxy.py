import toml
import os
from mitmproxy import proxy, options, http
from mitmproxy.tools.dump import DumpMaster
from detective.detective import Detective

BLACKLIST_FILE_PATH = "blacklist.toml"
PROXY_LISTEN_HOST = "127.0.0.1"
PROXY_LISTEN_PORT = 8080


class WAF:
    _detective = Detective()
    _blacklist = set()

    def __init__(self):
        self._load_blacklist_configuration(BLACKLIST_FILE_PATH)

    def _load_blacklist_configuration(self, blacklist_file_path):
        if os.path.exists(blacklist_file_path):
            self._blacklist = set(toml.load(blacklist_file_path).get("blacklist", []))
        else:
            open(blacklist_file_path, 'w').close()

    def _add_client_to_blacklist(self, attacker_ip_address):
        self._blacklist.add(attacker_ip_address)
        with open(BLACKLIST_FILE_PATH, 'a') as blacklist_file:
            toml.dump({"blacklist": self._blacklist}, blacklist_file)
            blacklist_file.close()

    def request(self, flow: http.HTTPFlow) -> None:
        """
        This function will check and handle received malicious requests
        :param flow: The user's request
        :type flow: http.HTTPFlow
        :return: None
        """
        client_ip_address = flow.client_conn.ip_address[0]
        is_client_blocked = client_ip_address in self._blacklist
        if is_client_blocked and flow.killable:
            flow.kill()
        else:
            if self._detective.investigate(flow.request):
                if flow.killable:
                    flow.kill()
                self._add_client_to_blacklist(client_ip_address)


addons = [
    WAF()
]


options = options.Options(listen_host=PROXY_LISTEN_HOST, listen_port=PROXY_LISTEN_PORT)
options.add_option("body_size_limit", int, 0, "")
options.add_option("intercept_active", bool, False, "")
options.add_option("keep_host_header", bool, True, "")
proxy_config = proxy.config.ProxyConfig(options)

proxy_server = DumpMaster(options)
proxy_server.server = proxy.server.ProxyServer(proxy_config)
proxy_server.addons.add(addons)

try:
    proxy_server.run()
except KeyboardInterrupt:
    proxy_server.shutdown()
