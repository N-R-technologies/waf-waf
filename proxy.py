from mitmproxy import proxy, options, http
from mitmproxy.tools.dump import DumpMaster
import os
# import toml # TODO: try use toml

HOST = "127.0.0.1"
PORT = 8080


class WAF:
    def __init__(self):
        self.blackList = []
        if os.path.exists("blacklist.txt"):
            if os.stat("blacklist.txt").st_size != 0:  # there is no need to read anything if the file is empty
                with open("blacklist.txt", 'r') as blacklist_file:  # load the saved blacklist to the program
                    # toml_content = toml.loads(blacklist_file.read())
                    self.blacklist = blacklist_file.read().split('\n')[:-1]
                    blacklist_file.close()
        else:
            with open("blacklist.txt", 'w') as blacklist_file:  # create the file if not exists
                blacklist_file.close()

    def http_connect(self, flow: http.HTTPFlow) -> None:
        # here we check if the latest connected client is in the blacklist
        # flow.server_conn object is used because the proxy is not reversed,
        # so it acts as if the client is the server and the server is the client
        if flow.server_conn.ip_address[0] in self.blacklist and flow.killable:
            flow.kill()

    def response(self, flow: http.HTTPFlow) -> None:
        enter_if_statement = False
        if enter_if_statement:  # We need to replace this with "is the flow malicious?"
            # TODO: kill the flow before appending the address to the blacklist (after merging)
            client_address = flow.server_conn.ip_address[0]
            self.blacklist.append(client_address)
            with open("blacklist.txt", 'a') as blacklist_file:  # saving the blacklist outside of the program
                blacklist_file.write(client_address + '\n')
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
