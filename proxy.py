from mitmproxy import proxy, options, http
from mitmproxy.tools.dump import DumpMaster
from detective import Detective

HOST = "127.0.0.1"
PORT = 8080


class MyAddon:
    _detective = Detective()

    def response(self, flow: http.HTTPFlow) -> None:
        if self._detective.detect(flow.request):
            # need to activate all the safety measures here
            pass


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
