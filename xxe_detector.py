import inspect
import xxe_info
from xxe_checks import XxeCheck
from risk_level import RiskLevel


def xxe_detector(request):
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
    finds_checks_counter = 0
    est_risk_level = 0
    statements_list = []
    attack_info = ""
    xxe_checks = inspect.getmembers(XxeCheck, predicate=inspect.isfunction)
    for xxe_check_name, xxe_check_function in xxe_checks:
        risk_level = xxe_check_function(request)
        if risk_level != RiskLevel.NO_RISK:
            finds_checks_counter += 1
            est_risk_level += risk_level
            attack_info += xxe_info.deep_info[xxe_check_name]
    return est_risk_level, attack_info
