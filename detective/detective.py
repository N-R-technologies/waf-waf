from importlib import import_module
from html import escape, unescape
import detective.toolbox as toolbox
from .attacks_logger import AttacksLogger


class Detective:
    INFO_INDEX = 2

    _magnifying_glass = toolbox.MagnifyingGlass()
    _assistant = toolbox.Assistant()
    _attacks_logger = AttacksLogger()
    _lenses = []

    def __init__(self):
        for lens in toolbox.lenses.__all__:
            lens_package = f"detective.toolbox.lenses.{lens}"
            basic_checks = getattr(import_module(".basic_checks", lens_package), "BasicChecks")
            advanced_checks = getattr(import_module(".advanced_checks", lens_package), "AdvancedChecks")
            info = import_module(".info", lens_package)
            self._lenses.append((basic_checks, advanced_checks, info))

    def investigate(self, request, client_ip):
        """
        This function will be called for every packet sent to the server.
        It will identify if the packet contains any kind of attack the WAF can protect from
        :param request: the user's request
        :param client_ip: the client ip address
        :type request: mitmproxy.http.HTTPFlow.request
        :type client_ip: ip
        :return: True if an attack was detected, otherwise, False
        :rtype: boolean
        """
        content = self._parse_request_content(request)
        if content is not None and content != "":
            for lens in self._lenses:
                attack_risks_findings, attack_info = self._magnifying_glass.detect(content, lens)
                found_risk = any(amount_of_risks > 0 for amount_of_risks in attack_risks_findings[toolbox.RiskLevels.NEGLIGIBLE:])
                if found_risk:
                    self._attacks_logger.add_attack_attempt(client_ip, content, attack_risks_findings)
                    if self._is_malicious_request(attack_risks_findings) or self._attacks_logger.is_continuity_attacks(client_ip):
                        self._assistant.set_findings(attack_risks_findings)
                        self._assistant.set_info(lens[self.INFO_INDEX].category, attack_info)
                        self._parse_escape_characters(request)
                        return True
        self._parse_escape_characters(request)
        return False

    def _parse_request_content(self, request):
        request_content = ""
        if request.method == "GET":
            for parameter in request.query.values():
                request_content += str(unescape(parameter)).lower()
            return request_content
        elif request.method == "POST":
            for content in request.urlencoded_form.values():
                request_content += str(content)
            return request_content.lower().replace('\n', "")
        return None

    def _is_malicious_request(self, findings):
        impact_level = 0
        for risk_occurrences, multiplying_factor in zip(findings[toolbox.RiskLevels.NEGLIGIBLE:], toolbox.risks_factors.__all__):
            impact_level += risk_occurrences * multiplying_factor
        return impact_level >= 1

    def _parse_escape_characters(self, request):
        if request.method == "GET":
            for parameter_name in request.query.keys():
                request.query[parameter_name] = escape(request.query[parameter_name])
        elif request.method == "POST":
            for parameter_name in request.urlencoded_form.keys():
                request.urlencoded_form[parameter_name] = escape(request.urlencoded_form[parameter_name])
