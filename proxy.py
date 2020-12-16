from mitmproxy import proxy, options, http
from mitmproxy.tools.dump import DumpMaster
import os

HOST = "127.0.0.1"
PORT = 8080


class WAF:
    def __init__(self):
        self.blackList = []
        if os.path.exists("blacklist.txt"):
            if os.stat("blacklist.txt").st_size != 0:  # there is no need to read anything if the file is empty
                with open("blacklist.txt", 'r') as blacklist_file:  # load the saved blacklist to the program
                    self.blacklist = blacklist_file.read().split('\n')[:-1]
                    blacklist_file.close()
        else:
            with open("blacklist.txt", 'w') as blacklist_file:  # create the file if not exists
                blacklist_file.close()

    def http_connect(self, flow: http.HTTPFlow):
#        if flow. in self.blacklist and flow.killable:  # check if the latest connected client is in the blacklist
#            flow.kill()
        pass

    def response(self, flow: http.HTTPFlow) -> None:
        with open("yex.txt", 'a') as nigga:  # open the file for reading
            nigga.write(str(flow.server_conn.spoof_source_address) + "\n")
            nigga.write(str(flow.server_conn.source_address) + "\n")
            nigga.write(str(flow.server_conn.server_certs) + "\n")
            nigga.write(str(flow.server_conn.get_state()) + "\n")
            nigga.close()
        enter_if_statement = False
        if enter_if_statement:  # We need to replace this with "is the flow malicious?"
            # TODO: kill the flow before appending the address to the blacklist
            client_address = ''  # flow.address...
            self.blacklist.append(client_address)
            with open("blacklist.txt", 'a') as blacklist_file:  # save the blacklist to the program
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
