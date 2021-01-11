import toml
import os
from mitmproxy import proxy, options, http
from mitmproxy.tools.dump import DumpMaster
from detective.detective import Detective

PROXY_LISTEN_HOST = "127.0.0.1"
PROXY_LISTEN_PORT = 8080


class WAF:
    BLACKLIST_FILE_PATH = "blacklist.toml"
    SERVER_INFO_FILE_PATH = "server_info.toml"
    is_first_request = True
    _detective = Detective()
    _blacklist = set()

    def __init__(self):
        self._load_blacklist_configuration(self.BLACKLIST_FILE_PATH)

    def _write_server_info_file(self, first_packet_flow):
        """
        function write the server info into the configuration file
        :param first_packet_flow: the flow of the first packet
        :type first_packet_flow: mitm flow
        :return: None
        """
        with open(self.SERVER_INFO_FILE_PATH, 'w') as server_info_file:
            toml.dump({"host": first_packet_flow.request.host_header}, server_info_file)
            server_info_file.close()

    def _load_blacklist_configuration(self, blacklist_file_path):
        """
        function load the blacklist configuration file
        :param blacklist_file_path: the path of the blacklist file
        :type: str
        :return: None
        """
        if os.path.exists(blacklist_file_path):
            self._blacklist = set(toml.load(blacklist_file_path).get("blacklist", []))
        else:
            open(blacklist_file_path, 'w').close()

    def _add_client_to_blacklist(self, attacker_ip_address):
        """
        function add client's ip to the blacklist file
        :param attacker_ip_address: the ip of the attacker
        :type attacker_ip_address: str
        :return: None
        """
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
        if self.is_first_request:
            self.is_first_request = False
            self._write_server_info_file(flow)
        client_ip_address = flow.client_conn.ip_address[0]
        is_client_blocked = client_ip_address in self._blacklist
        if is_client_blocked and flow.killable:
            flow.kill()
        elif self._detective.investigate(flow.request) and flow.killable:
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
