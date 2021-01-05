import inspect
from risk_levels import RiskLevels


class Detector:
    def detect(self, request, attack_basic_checks, attack_advanced_checks, attack_info):
        """
        This function will be called by the detective for every request that should reach the server
        It will return the risk levels of the given attack and information about it
        :param request: the request that goes into the server
        :param attack_basic_checks: the attack's basic checks
        :param attack_advanced_checks: the attack's advanced checks
        :param attack_info: the attack's information
        :type request: string
        :type attack_basic_checks: the attack's BasicChecks class
        :type attack_advanced_checks: the attack's AdvancedChecks class
        :type attack_info: the attack's info file
        :return: risk levels of the given attack and information about it
        :rtype: tuple
        """
        risk_findings = [0] * len(RiskLevels)
        all_risks_info = []

        basic_checks = inspect.getmembers(attack_basic_checks, predicate=inspect.isfunction)
        for basic_check_name, basic_check in basic_checks:
            basic_check_result = basic_check(request)
            risk_findings[basic_check_result] += 1
            if basic_check_result > RiskLevels.NO_RISK:
                all_risks_info.append(attack_info.deep_info[basic_check_name])

        advanced_checks = inspect.getmembers(attack_advanced_checks, predicate=inspect.isfunction)
        for advanced_check_name, advanced_check in advanced_checks:
            advanced_check_result = advanced_check(request)
            risk_findings[advanced_check_result] += 1
            if advanced_check_result > RiskLevels.NO_RISK:
                all_risks_info.append(attack_info.deep_info[advanced_check_name])

        return risk_findings, all_risks_info
