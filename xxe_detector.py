import inspect
import xxe_info
from xxe_checks import XxeCheck
from risk_level import RiskLevel


class XxeDetector:
    def _summarize_info(self, risks_info):
        """
        This function will summarize all the information about the attack
        :param risks_info: all the information about the detected risks
        :type risks_info: string
        :return: the summarized information about the attack
        :rtype: string
        """
        if not risks_info:
            risks_info = "No risks found"
        return xxe_info.general_info + "\n\n" + risks_info + "\n\n" + xxe_info.links_for_info

    def detect(self, request):
        """
        This is the main function of the library. the detective will
        call it over every time a request from a user to the server is received
        :param request: the request that goes into the server
        :type request: string
        :return: the estimated risk level of the packet
        :return: the information about the attack that occurred
        :rtype: integer
        :rtype: string
        """
        findings_graph = [0] * RiskLevel.NUM_OF_RISKS
        all_risks_info = ""

        checks = inspect.getmembers(XxeCheck, predicate=inspect.isfunction)
        for check_name, check in checks:
            check_result = check(request)
            findings_graph[check_result] += 1
            if check_result > RiskLevel.NO_RISK:
                all_risks_info += xxe_info.deep_info[check_name]
        return self._summarize_info(all_risks_info), findings_graph
