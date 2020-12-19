import toml
import os
from mitmproxy import proxy, options, http
from mitmproxy.tools.dump import DumpMaster

BLACKLIST_FILE_PATH = "blacklist.toml"
PROXY_LISTEN_HOST = "127.0.0.1"
PROXY_LISTEN_PORT = 80800


class WAF:
    _blacklist = set()

    def __init__(self):
        self._load_blacklist_configuration(BLACKLIST_FILE_PATH)

    def _load_blacklist_configuration(self, blacklist_file_path):
        if os.path.exists(blacklist_file_path):
            # "None" can't be loaded into a set, so an empty string is being used instead
            self._blacklist = set(toml.load(blacklist_file_path).get("blacklist", ""))
        else:
            open(blacklist_file_path, 'w').close()

    def _add_client_to_blacklist(self, attacker_ip_address):
        self._blacklist.add(attacker_ip_address)
        with open(BLACKLIST_FILE_PATH, 'w') as blacklist_file:
            toml.dump({"blacklist": self._blacklist}, blacklist_file)
            blacklist_file.close()

    def response(self, flow: http.HTTPFlow) -> None:  # TODO: change the function to "request" after CR
        """
        This function will check and handle received malicious requests
        :param flow: The user's request
        :type flow: http.HTTPFlow
        :return: None
        """
        client_ip_address = flow.server_conn.ip_address[0]  # TODO: probably change "server_conn" to "client_conn" after changing to "request"
        is_client_blocked = client_ip_address in self._blacklist
        if is_client_blocked and flow.killable:
            flow.kill()
        else:
            enter_if_statement = False
            if enter_if_statement:  # TODO: replace this with "is the flow malicious?"
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

proxy = DumpMaster(options)
proxy.server = proxy.server.ProxyServer(proxy_config)
proxy.addons.add(addons)

try:
    proxy.run()
except KeyboardInterrupt:
    proxy.shutdown()
