import toml
import os
from mitmproxy import proxy, options, http
from mitmproxy.tools.dump import DumpMaster

BLACKLIST_FILE_PATH = "blacklist.toml"
TOML_BLACKLIST = "blacklist"  # the blacklist array's name in the toml file
PROXY_LISTEN_HOST = "127.0.0.1"
PROXY_LISTEN_PORT = 8080


class WAF:
    _blacklist = set()

    def __init__(self):
        self._load_blacklist_configuration(BLACKLIST_FILE_PATH, TOML_BLACKLIST)

    def _load_blacklist_configuration(self, blacklist_file_path, toml_blacklist):
        if os.path.exists(blacklist_file_path):
            try:  # load the saved blacklist to the program
                self._blacklist = set(toml.load(blacklist_file_path)[toml_blacklist])
            except KeyError:  # toml file is empty and cannot find the "blacklist" array
                pass
        else:
            open(blacklist_file_path, 'w').close()  # create an empty blacklist file if not exists

    def response(self, flow: http.HTTPFlow) -> None:  # TODO: change the function to "request" after CR
        """
        This function will check and handle received malicious requests
        :param flow: The user's request
        :type flow: http.HTTPFlow
        :return: None
        """
        # check if the latest connected client is in the blacklist
        if flow.server_conn.ip_address[0] in self._blacklist and flow.killable:
            flow.kill()
        else:
            enter_if_statement = False
            if enter_if_statement:  # TODO: replace this with "is the flow malicious?"
                if flow.killable:
                    flow.kill()
                attacker_ip_address = flow.server_conn.ip_address[0]
                self._blacklist.add(attacker_ip_address)
                with open(BLACKLIST_FILE_PATH, 'w') as blacklist_file:  # saving the blacklist outside of the program
                    toml.dump({TOML_BLACKLIST: self._blacklist}, blacklist_file)
                    blacklist_file.close()


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
