import re
from urllib.parse import urlparse
NO_RISK = 0
UNIMPORTANT_RISK = 1
VERY_LITTLE_RISK = 2
LITTLE_RISK = 3
VERY_LOW_RISK = 4
LOW_RISK = 5
MEDIUM_RISK = 6
LARGE_RISK = 7
HIGH_RISK = 8
VERY_DANGEROUS = 9
"""the xxe detector is now check a simple pattern of xxe injection, need to develop this pattern and 
block other types of xxe injection"""


def xxe_detector(request):
    pass


def check_xxe_information_disclosure(request):
    """function check if the user try to get information from the server machine by xml injection the xml parser
    :param request: the request
    :return: the dangerous level according the findings
    :rtype: integer"""
    search_xxe_result = re.search(r"""<!\s*(?P<component>element|entity\s+.*system\s+)""", request)
    if search_xxe_result:
        if search_xxe_result.group("component") != "element":
            return VERY_DANGEROUS if check_blind_xxe(request) else HIGH_RISK
        return MEDIUM_RISK


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
    return VERY_LOW_RISK if re.search(r"""<!(\[cdata\[|\-\-)""", request) else NO_RISK
