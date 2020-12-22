import inspect
from risk_level import RiskLevel
import sqlinjection_info
from sqli_basic_checks import SqlIBasicChecks
from sqli_advanced_checks import SqlIAdvancedChecks


NUM_OF_RISKS = 9


def detector(request):
    """
    this is the main function of the library, in the proxy server you just need to run it over every request
    packet that reach the server, return the attack detected and the info about it
    :param request: the request that goes into the server
    :type request: string
    :return: tuple of list of risk level and the info about the attack
    :rtype: tuple
    """
    risk_conclusion = [0] * NUM_OF_RISKS
    all_risks_info = ""

    basic_checks = inspect.getmembers(SqlIBasicChecks, predicate=inspect.isfunction)
    for basic_check_name, basic_check in basic_checks:
        est_risk_from_basic = basic_check(request)
        if est_risk_from_basic != RiskLevel.NO_RISK:
            print(basic_check_name)
            risk_conclusion[int(est_risk_from_basic)-1] += 1
            all_risks_info += sqlinjection_info.deep_info[basic_check_name]

    #  finish all the basic checks, now the advanced check take part
    advanced_checks = inspect.getmembers(SqlIAdvancedChecks, predicate=inspect.isfunction)
    for advanced_check_name, advanced_check in advanced_checks:
        est_risk_from_advanced = advanced_check(request)
        if est_risk_from_advanced != RiskLevel.NO_RISK:
            risk_conclusion[int(est_risk_from_advanced) - 1] += 1
            all_risks_info += sqlinjection_info.deep_info[advanced_check_name]
    return concat_info(all_risks_info), risk_conclusion


def concat_info(risks_info):
    """
    function concat all the info about the attack
    :param risks_info: all the info about the detected risks
    :type risks_info: string
    :return: the concat information about the attack
    :rtype: string
    """
    return sqlinjection_info.general_info + '\n' + risks_info + '\n' + sqlinjection_info.links_for_info
