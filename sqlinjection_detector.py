import re
"""this is the main function which will called from the proxy,
here we will call to all the sub function"""
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


def find_sql_injection(request):
    # need to call al the check function and calculate the risk level
    pass


"""check if the user try to run from the input common MySQL function “find_in_set”
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def find_in_set(request):
    if re.search("\bfind_in_set\b.*?\(.+?,.+?\)", request):
        return MEDIUM_RISK
    return NO_RISK


"""check if the user try to run from the input SQLite information disclosure “sqlite_master”
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def find_master_access(request):
    if re.search("\bsqlite_master\b", request):
        return LARGE_RISK
    return NO_RISK


"""check if the user try to run from the input MySQL information disclosure “mysql.user”
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_user_disclosure(request):
    if re.search("\bmysql.*?\..*?user\b", request):
        return LITTLE_RISK
    return NO_RISK


"""check if the user try to run from the input Common SQL command “union select”
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_union_select(request):
    if re.search("\bunion\b.+?\bselect\b", request):
        return LITTLE_RISK
    return NO_RISK


"""check if the user try to run from the input Common SQL command “update”
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_update_command(request):
    if re.search("\bupdate\b.+?\bset\b", request):
        return LITTLE_RISK
    return NO_RISK


"""check if the user try to run from the input Common SQL command “drop”
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_drop_command(request):
    if re.search("\bdrop\b.+?\b(database|table)\b", request):
        return LITTLE_RISK
    return NO_RISK


"""check if the user try to run from the input Common SQL command “delete”
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_delete_command(request):
    if re.search("\bdelete\b.+?\bfrom\b", request):
        return LITTLE_RISK
    return NO_RISK


"""check if the user try to run from the input Common SQL comment syntax
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_comment_syntax(request):
    if re.search("--.+?", request):
        return VERY_LITTLE_RISK
    return NO_RISK


"""check if the user try to run from the input Common mongoDB commands
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_mongo_db_command(request):
    if re.search("\[\$(ne|eq|lte?|gte?|n?in|mod|all|size|exists|type|slice|or)\]", request):
        return MEDIUM_RISK
    return NO_RISK


"""check if the user try to run from the input Common C-style comment
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_cstyle_comment(request):
    if re.search(" \/\*.*?\*\/", request):
        return LITTLE_RISK
    return NO_RISK


"""check if the user try to run from the input blind mysql benchmark
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_blind_benchmark(request):
    if re.search("bbenchmark\b.*?\(.+?,.+?\)", request):
        return MEDIUM_RISK
    return NO_RISK













