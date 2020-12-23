import inspect
import xxe_info
from xxe_checks import XxeChecks
from risk_level import RiskLevel


class XxeDetector:
    @staticmethod
    def detect(request):
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
        findings_graph = [0 for risk in range(RiskLevel.NUM_OF_RISKS)]
        all_risks_info = ""

        checks = inspect.getmembers(XxeChecks, predicate=inspect.isfunction)
        for check_name, check in checks:
            check_result = check(request)
            findings_graph[check_result] += 1
            if check_result > RiskLevel.NO_RISK:
                all_risks_info += xxe_info.deep_info[check_name]
        return XxeDetector.summarize_info(all_risks_info), findings_graph

    @staticmethod
    def summarize_info(risks_info):
        """
        This function will summarize all the information about the attack
        :param risks_info: all the information about the detected risks
        :type risks_info: string
        :return: the summarized information about the attack
        :rtype: string
        """
        if not risks_info:
            risks_info = "* No risks detected\n"
        return xxe_info.general_info + "\n\nDetected risks:\n" + risks_info + "\n" + xxe_info.links_for_info
