import inspect
from risk_level import RiskLevel
import sqlinjection_info
from sqli_basic_checks import SqlIBasicCheck
from sqli_advanced_checks import SqlIAdvancedCheck


def detector(request):
    """
    this is the main function of the library, in the proxy server you just need to run it over every request
    packet that reach the server
    :param request: the request that goes into the server
    :type request: string
    :return: if the detector detect sql injection in thr the packet
    :return: the estimated risk level of the packer
    :return: the information about the attack that occurred
    :rtype: boolean
    :rtype: integer
    :rtype: string
    """
    counter_finds_basic_checks = 0
    counter_finds_advanced_checks = 0
    est_basic_risk_level = 0
    est_advanced_risk_level = 0
    risk_to_add = 0
    statements_list = []
    attack_info = ""
    for function in inspect.getmembers(SqlIBasicCheck, predicate=inspect.isfunction):
        if function[1](request):
            counter_finds_basic_checks += 1
            attack_info += sqlinjection_info.deep_info[function[0]]
    if counter_finds_basic_checks == 1:
        est_basic_risk_level = RiskLevel.VERY_LITTLE_RISK
    elif (counter_finds_basic_checks > 1) and (counter_finds_basic_checks < 3):
        est_basic_risk_level = RiskLevel.VERY_LOW_RISK
    elif counter_finds_basic_checks >= 3:
        est_basic_risk_level = RiskLevel.LOW_RISK
    #  finish all the basic checks, now the advanced check take part
    if ';' in request:
        statements_list = request.split(';')
    else:
        statements_list.append(request)
    if statements_list[-1] == '':
        statements_list = statements_list[:-1]
    for sub_statement in statements_list:  # for example if the request contains couple of queries like:
        #  or 1 = 1; drop table table_name
        sub_statement = sub_statement.strip()  # remove spaces from begin and end of the sub_statement
        # for every sub statement check the advanced detection functions
        for or_statement in sub_statement.split("or")[1:]:  # checks for every statement if its an 'or' statement
            find, risk_to_add = SqlIAdvancedCheck.check_or(or_statement)
            if find:
                est_advanced_risk_level += risk_to_add
                counter_finds_advanced_checks += 1
                attack_info += sqlinjection_info.deep_info["risk_to_add"]
        for function in inspect.getmembers(SqlIAdvancedCheck, predicate=inspect.isfunction):
            if function[0] != "check_or":
                find, risk_to_add = function[1](sub_statement)
                if find:
                    est_advanced_risk_level += risk_to_add
                    counter_finds_advanced_checks += 1
                    attack_info += sqlinjection_info.deep_info[function[0]]
    try:
        est_advanced_risk_level /= counter_finds_advanced_checks
    except ZeroDivisionError:
        return (False, None, None)
    if est_advanced_risk_level >= RiskLevel.MEDIUM_RISK or est_basic_risk_level >= RiskLevel.VERY_LOW_RISK:
        est_risk_level = (est_basic_risk_level + est_advanced_risk_level) / 2
        info = sqlinjection_info.general_info + attack_info + sqlinjection_info.links_for_info
        return (True, est_risk_level, info)
    return (False, None, None)