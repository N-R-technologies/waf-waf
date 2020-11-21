from mitmproxy import proxy, options
from mitmproxy.tools.dump import DumpMaster

import typing

from mitmproxy import command
from mitmproxy import ctx
from mitmproxy import flow

class MyAddon:
    @command.command("myaddon.addheader")
    def addheader(self, flows: typing.Sequence[flow.Flow]) -> None:
        for f in flows:
            f.request.headers["myheader"] = "value"
        ctx.log.alert("done")


addons = [
    MyAddon()
]


opts = options.Options(listen_host='127.0.0.1', listen_port=8080)
opts.add_option("body_size_limit", int, 0, "")
opts.add_option("keep_host_header", bool, True, "")
pconf = proxy.config.ProxyConfig(opts)

m = DumpMaster(None)
m.server = proxy.server.ProxyServer(pconf)
m.addons.add(addons)

try:
    m.run()
except KeyboardInterrupt:
    m.shutdown()