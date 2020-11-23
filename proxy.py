from mitmproxy import proxy, options, http
from mitmproxy.tools.dump import DumpMaster

HOST = "127.0.0.1"
PORT = 8080


class MyAddon:
    # the response function contains the request data, but the request function doesn't contains
    # the response data, so using the response function gives us more information about the HTTPFlow
    def response(self, flow: http.HTTPFlow) -> None:
        # the HTTPFlow data is being written to proxy_test.txt for testing purposes
        f = open("proxy_test.txt", 'a')
        f.write(str(flow) + '\n')
        f.close()


addons = [
    MyAddon()
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
