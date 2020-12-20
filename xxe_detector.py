import re
from urllib.parse import urlparse
from risk_level import RiskLevel
from xxe_info import XxeInfo
"""the xxe detector is now check a simple pattern of xxe injection, need to develop this pattern and 
block other types of xxe injection"""


def detector(request):
    attack_info = ""
    information = XxeInfo()
    dangerous_level = RiskLevel.NO_RISK
    if check_xxe_information_disclosure(request):
        if check_blind_xxe(request):
            information.set_attack_info("blind_xxe")
            attack_info = information.get_info()
            dangerous_level += RiskLevel.VERY_DANGEROUS
        else:
            information.set_attack_info("xxe_information_disclosure")
            attack_info = information.get_info()
            dangerous_level += RiskLevel.HIGH_RISK
    if check_xxe_comments(request):
        information.set_attack_info("xxe_comment")
        attack_info = information.get_info()
    return dangerous_level, attack_info


def check_xxe_information_disclosure(request):
    """function check if the user try to get information from the server machine by xml injection the xml parser
    :param request: the request
    :return: the dangerous level according the findings
    :rtype: integer"""
    search_xxe_result = re.search(r"""<!\s*(?P<component>element|entity\s+.*system\s+)""", request)
    return True if search_xxe_result else False


def check_blind_xxe(request):
    """function check if the user try to send his information disclosure to some server or website
    :param request: the request
    :return: True if he tries to sent information to website, otherwise false
    :rtype: boolean"""
    result = re.search(r""".*?(?:'|\")(?P<url>.*?)(?:'|\")""", request)
    if result:
        url = result.group("url")
        if url:
            parse_result = urlparse(url)
            if parse_result.scheme != '' and parse_result.netloc != '':
                return True
    return False


def check_xxe_comments(request):
    """function check if the request contains some xxe comment tags
    :param request: the request from user
    :type request: string
    :return the dangerous level according the findings
    :rtype: integer"""
    return True if re.search(r"""<!(\[cdata\[|\-\-)""", request) else False
