import inspect
from detective.risk_levels import RiskLevels

BASIC_CHECKS = 0
ADVANCED_CHECKS = 1
INFO = 2


class MagnifyingGlass:
    def detect(self, request, lens):
        """
        This function will be called by the detective for every request that should reach the server
        It will return the risk levels of the given attack and information about it
        :param request: the request that goes into the server
        :param lens: the attack's lens that contains it's basic and advanced checks and information
        :type request: string
        :type lens: attack's basic and advanced checks - classes. attack's information - module
        :return: risk levels of the given attack and information about it
        :rtype: tuple
        """
        risk_findings = [0] * len(RiskLevels)
        all_risks_info = []

        basic_checks = inspect.getmembers(lens[BASIC_CHECKS], predicate=inspect.isfunction)
        for basic_check_name, basic_check in basic_checks:
            basic_check_result = basic_check(request)
            risk_findings[basic_check_result] += 1
            if basic_check_result > RiskLevels.NO_RISK:
                all_risks_info.append(lens[INFO].deep_info[basic_check_name])

        advanced_checks = inspect.getmembers(lens[ADVANCED_CHECKS], predicate=inspect.isfunction)
        for advanced_check_name, advanced_check in advanced_checks:
            advanced_check_result = advanced_check(request)
            risk_findings[advanced_check_result] += 1
            if advanced_check_result > RiskLevels.NO_RISK:
                all_risks_info.append(lens[INFO].deep_info[advanced_check_name])

        return risk_findings, all_risks_info
