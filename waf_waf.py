from mitmproxy import proxy, options, http
from mitmproxy.tools.dump import DumpMaster
from waf_data import DataManager
from detective import Detective
from detective.toolbox.brute_force import BruteForceDetector, CaptchaImplementer

PROXY_LISTEN_HOST = "127.0.0.1"
PROXY_LISTEN_PORT = 8080


class WAF:
    MAX_ATTACK_ATTEMPTS = 2

    _detective = Detective()
    _brute_force_detector = BruteForceDetector()
    _captcha_implementer = CaptchaImplementer()
    _data_manager = DataManager()
    _blacklist = set()
    _attack_attempts = dict()
    _is_first_request = True

    def __init__(self):
        self._blacklist = self._data_manager.load_blacklist_configuration()

    def request(self, flow: http.HTTPFlow) -> None:
        if self._is_first_request:
            self._data_manager.write_server_info_configuration(flow.request)
            self._is_first_request = False
        client_ip_address = flow.client_conn.ip_address[0]
        is_client_blocked = client_ip_address in self._blacklist
        if (is_client_blocked or self._brute_force_detector.is_request_blocked(flow.request, client_ip_address)) and flow.killable:
            flow.kill()
        elif self._data_manager.is_wrong_diagnosis_request(flow.request):
            self._data_manager.add_client_to_wrong_diagnosis(client_ip_address)
        else:
            self._brute_force_detector.count_user_requests(flow.request, client_ip_address)
            if self._detective.investigate(flow.request, client_ip_address):
                if client_ip_address in self._attack_attempts.keys() and self._attack_attempts[client_ip_address] >= self.MAX_ATTACK_ATTEMPTS:
                    if flow.killable:
                        flow.kill()
                    self._data_manager.add_client_to_blacklist(client_ip_address, self._blacklist)
                else:
                    flow.request.headers["Host"] = "No such host"
                    if client_ip_address in self._attack_attempts.keys():
                        self._attack_attempts[client_ip_address] += 1
                    else:
                        self._attack_attempts[client_ip_address] = 1
                    if "Referer" in flow.request.headers.keys():
                        referer = flow.request.headers["Referer"]
                    else:
                        referer = "www.google.com"
                    flow.response = http.HTTPResponse.make(400, self._data_manager.get_warning_message(self._attack_attempts[client_ip_address], self.MAX_ATTACK_ATTEMPTS, referer), {"content-type": "text/html"})

    def response(self, flow: http.HTTPFlow) -> None:
        user_ip_address = flow.client_conn.ip_address[0]
        flow.response = self._brute_force_detector.add_delay(flow.response, user_ip_address)
        login_url = self._captcha_implementer.get_login_url(flow.request)
        if login_url is not None:
            if not self._captcha_implementer.has_login_permission(user_ip_address):
                captcha = self._captcha_implementer.implement(user_ip_address, login_url)
                if captcha is not None:
                    flow.response = http.HTTPResponse.make(200, captcha, {"content-type": "text/html"})
            else:
                self._captcha_implementer.remove_login_permission(user_ip_address)


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
