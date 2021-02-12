import toml
import os
from mitmproxy import proxy, options, http
from mitmproxy.tools.dump import DumpMaster
from detective import Detective

PROXY_LISTEN_HOST = "127.0.0.1"
PROXY_LISTEN_PORT = 8080


class WAF:
    BLACKLIST_FILE_PATH = "blacklist.toml"
    SERVER_INFO_FILE_PATH = "server_info.toml"
    MAX_ATTACK_ATTEMPTS = 2

    _detective = Detective()
    _blacklist = set()
    _is_first_request = True

    def __init__(self):
        self._load_blacklist_configuration(self.BLACKLIST_FILE_PATH)
        self._attack_attempts = dict()

    def _get_warning_message(self, client_ip_address):
        warning_msg = "<html>" \
                      '<body style="background-color:#211f20; color:red; font-family:sans-serif; text-align: center;">' \
                      '<h1>WARNING!!!!!!</h1>' \
                      '<img src = "https://lh3.googleusercontent.com/gy5WPTVkuE1zCU0UC9R5KuKcPFwYXkyKsxoCBMyLEzY-oIRzblcsyTMZeLbayh697ysTk8W3QUKjWjCmPaXawsssus-agH3LGHUnm2-gSP8wcHQNnQ=w1280" alt = "warning" style="width:400px;height:300px;">'\
                      '<h1>You getting this message because our WAF detect your attack attempt</h1>' \
                      f'<h1>Be careful! if we are going to find you doing this {self.MAX_ATTACK_ATTEMPTS + 1 - self._attack_attempts[client_ip_address]} more times</h1>' \
                      '<h1>You will be banned from the server permanently!!</h1>' \
                      '<h1>Dont try to refresh this page!</h1>' \
                      '<img src = "https://lh6.googleusercontent.com/YReznLOhSl3yiu9GhSfouZDUDjz-ocptXuvtIoOXKLZcBZLrf7Q5FfkdJfY_pYccrkDTSGPUPvb-gPZ8g6LHP65rOKpMtLDozzgRvzBJf6qYBLiF-nc=w1280" alt = "waf logo" style="width:500px;height:300px;"'\
                      "</body>" \
                      "</html>"
        return warning_msg

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
        if is_client_blocked and flow.killable:
            flow.kill()
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

                    flow.response = http.HTTPResponse.make(
                        400,
                        self._get_warning_message(client_ip_address),
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
