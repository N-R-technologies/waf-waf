from mitmproxy import proxy, options, ctx
from mitmproxy.tools.dump import DumpMaster

HOST = "127.0.0.1"
PORT = 8080


class MyAddon:
    def __init__(self):
        self.counter = 0

    def response(self, flow) -> None:
        self.counter += 1
        ctx.log.info("%d responses have been received so far" % self.counter)


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
