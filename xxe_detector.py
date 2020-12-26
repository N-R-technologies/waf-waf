import inspect
import xxe_info
from xxe_basic_checks import XxeBasicChecks
from xxe_advanced_checks import XxeAdvancedChecks
from risk_level import RiskLevel


class Detector:
    @staticmethod
    def detect(request):
        """
        This is the main function of the library. the detective will
        call it over every time a request from a user to the server is received
        :param request: the request that goes into the server
        :type request: string
        :return: tuple of risk levels list and the information about the attack
        :rtype: tuple
        """
        findings_graph = [0 for risk in range(len(RiskLevel))]
        all_risks_info = ""

        basic_checks = inspect.getmembers(XxeBasicChecks, predicate=inspect.isfunction)
        for basic_check_name, basic_check in basic_checks:
            basic_check_result = basic_check(request)
            findings_graph[basic_check_result] += 1
            if basic_check_result > RiskLevel.NO_RISK:
                all_risks_info += xxe_info.deep_info[basic_check_name]

        #  finish all the basic checks, now the advanced check take part
        advanced_checks = inspect.getmembers(XxeAdvancedChecks, predicate=inspect.isfunction)
        for advanced_check_name, advanced_check in advanced_checks:
            advanced_check_result = advanced_check(request)
            findings_graph[advanced_check_result] += 1
            if advanced_check_result > RiskLevel.NO_RISK:
                all_risks_info += xxe_info.deep_info[advanced_check_name]

        return Detector.summarize_info(all_risks_info), findings_graph

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
        return "General Information XXE attack:\n" + xxe_info.general_info + "\n\nDetected risks:\n" + risks_info + '\n' + xxe_info.links_for_info
