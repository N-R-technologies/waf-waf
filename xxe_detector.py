import inspect
import xxe_info
from xxe_checks import XxeCheck
from risk_level import RiskLevel


def concat_info(risks_info):
    """
    This function will concat all the information about the attack
    :param risks_info: all the information about the detected risks
    :type risks_info: string
    :return: the concat information about the attack
    :rtype: string
    """
    return xxe_info.general_info + "\n\n" + risks_info + "\n\n" + xxe_info.links_for_info


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
    risk_conclusion = [0] * RiskLevel.NUM_OF_RISKS
    all_risks_info = ""

    xxe_checks = inspect.getmembers(XxeCheck, predicate=inspect.isfunction)
    for xxe_check_name, xxe_check_function in xxe_checks:
        est_risk_level = xxe_check_function(request)
        if est_risk_level != RiskLevel.NO_RISK:
            risk_conclusion[est_risk_level - 1] += 1
            all_risks_info += xxe_info.deep_info[xxe_check_name]
    print(risk_conclusion)
    return concat_info(all_risks_info), risk_conclusion
