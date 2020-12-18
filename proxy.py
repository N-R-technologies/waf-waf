from mitmproxy import proxy, options, http
from mitmproxy.tools.dump import DumpMaster
import os
import toml

HOST = "127.0.0.1"
PORT = 8080


class WAF:
    def __init__(self):
        self.blacklist = []
        if os.path.exists("blacklist.toml"):
            if os.stat("blacklist.toml").st_size != 0:  # there is no need to read anything if the file is empty
                self.blacklist = toml.load("blacklist.toml")['blacklist']  # load the saved blacklist to the program
        else:
            with open("blacklist.toml", 'w') as blacklist_file:  # create an empty blacklist toml file if not exists
                blacklist_file.close()

    def response(self, flow: http.HTTPFlow) -> None:
        # check if the latest connected client is in the blacklist
        # flow.server_conn object is used because the proxy is not reversed,
        # so it acts as if the client is the server and the server is the client
        if flow.server_conn.ip_address[0] in self.blacklist and flow.killable:
            flow.kill()
        else:
            enter_if_statement = False
            if enter_if_statement:  # we need to replace this with "is the flow malicious?"
                if flow.killable:
                    flow.kill()
                attacker_ip_address = flow.server_conn.ip_address[0]
                self.blacklist.append(attacker_ip_address)
                with open("blacklist.toml", 'w') as blacklist_file:  # saving the blacklist outside of the program
                    toml.dump({'blacklist': self.blacklist}, blacklist_file)
                    blacklist_file.close()


addons = [
    WAF()
]

options = options.Options(listen_host=HOST, listen_port=PORT)
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
