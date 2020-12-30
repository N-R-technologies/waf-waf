import inspect
import info
from basic_checks import BasicChecks
from advanced_checks import AdvancedChecks
from risk_level import RiskLevel


class Detector:
    def detect(self, request):
        """
        This function will be called by the detective for every request that should reach the server
        It will return the risk levels of XXE attack and information about it
        :param request: the request that goes into the server
        :type request: string
        :return: tuple of risk levels list and the information about the attack
        :rtype: tuple
        """
        risk_findings = [0] * len(RiskLevel)
        all_risks_info = ""

        basic_checks = inspect.getmembers(BasicChecks, predicate=inspect.isfunction)
        for basic_check_name, basic_check in basic_checks:
            basic_check_result = basic_check(request)
            risk_findings[basic_check_result] += 1
            if basic_check_result > RiskLevel.NO_RISK:
                all_risks_info += info.deep_info[basic_check_name]

        advanced_checks = inspect.getmembers(AdvancedChecks, predicate=inspect.isfunction)
        for advanced_check_name, advanced_check in advanced_checks:
            advanced_check_result = advanced_check(request)
            risk_findings[advanced_check_result] += 1
            if advanced_check_result > RiskLevel.NO_RISK:
                all_risks_info += info.deep_info[advanced_check_name]

        return Detector.summarize_info(all_risks_info), risk_findings

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
        risks_list = []
        risks_list.append("General Information XXE attack:\n" + info.general_info + "\n\nDetected risks:\n")
        risks_list.append(risks_info + '\n')
        risks_list.append(info.links_for_info)
        return risks_list

    @property
    def category(self):
        return "XXE"
