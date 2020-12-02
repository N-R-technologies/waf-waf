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


def check_risk_found(request, regex_expression, risk):
    if re.search(regex_expression, request):
        return risk
    return NO_RISK


"""check if the user try to run from the input common MySQL function “find_in_set”
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def find_in_set(request):
    return check_risk_found(request, r"\bfind_in_set\b.*?\(.+?,.+?\)", MEDIUM_RISK)


"""check if the user try to run from the input SQLite information disclosure “sqlite_master”
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def find_master_access(request):
    return check_risk_found(request, r"\bsqlite_master\b", LARGE_RISK)


"""check if the user try to run from the input MySQL information disclosure “mysql.user”
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_user_disclosure(request):
    return check_risk_found(request, r"\bmysql.*?\..*?user\b", LITTLE_RISK)


"""check if the user try to run from the input Common SQL command “union select”
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_union_select(request):
    return check_risk_found(request, r"\bunion\b.+?\bselect\b", LITTLE_RISK)


"""check if the user try to run from the input Common SQL command “update”
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_update_command(request):
    return check_risk_found(request, r"\bupdate\b.+?\bset\b", LITTLE_RISK)


"""check if the user try to run from the input Common SQL command “drop”
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_drop_command(request):
    return check_risk_found(request, r"\bdrop\b.+?\b(database|table)\b", LITTLE_RISK)


"""check if the user try to run from the input Common SQL command “delete”
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_delete_command(request):
    return check_risk_found(request, r"\bdelete\b.+?\bfrom\b", LITTLE_RISK)


"""check if the user try to run from the input Common SQL comment syntax
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_comment_syntax(request):
    return check_risk_found(request, r"--.+?", VERY_LITTLE_RISK)


"""check if the user try to run from the input Common mongoDB commands
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_mongo_db_command(request):
    return check_risk_found(request, r"\[\$(ne|eq|lte?|gte?|n?in|mod|all|size|exists|type|slice|or)\]", MEDIUM_RISK)


"""check if the user try to run from the input Common C-style comment
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_cstyle_comment(request):
    return check_risk_found(request, r" \/\*.*?\*\/", LITTLE_RISK)


"""check if the user try to run from the input blind sql benchmark
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_blind_benchmark(request):
    return check_risk_found(request, r"bbenchmark\b.*?\(.+?,.+?\)", MEDIUM_RISK)


"""check if the user try to run from the input blind sql sleep
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_blind_sql_sleep(request):
    return check_risk_found(request, r"\bsleep\b.*?\(.+?\)", VERY_LITTLE_RISK)


"""check if the user try to run from the input blind mysql disclosure "load_file"
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_load_file_disclosure(request):
    return check_risk_found(request, r"\bload_file\b.*?\(.+?\)", LARGE_RISK)


"""check if the user try to run from the input blind mysql disclosure "load_data"
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_load_data_disclosure(request):
    return check_risk_found(request, r"\bload\b.*?\bdata\b.*?\binfile\b.*?\binto\b.*?\btable\b", LARGE_RISK)


"""check if the user try to run from the input MySQL file write "into outfile"
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_write_into_outfile(request):
    return check_risk_found(request, r"\bselect\b.*?\binto\b.*?\b(out|dump)file\b", HIGH_RISK)


"""check if the user try to run from the input the command concat
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_concat_command(request):
    return check_risk_found(request, r"\b(group_)?concat(_ws)?\b.*?\(.+?\)", LITTLE_RISK)


"""check if the user try to run from the input mysql information disclosure
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_information_disclosure(request):
    return check_risk_found(request, r"\binformation_schema\b", LARGE_RISK)


"""check if the user try to run from input the pgsql sleep command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_sleep_pg_command(request):
    return check_risk_found(request, r"\bpg_sleep\b.*?\(.+?\)", MEDIUM_RISK)


"""check if the user try to run from input the blind tsql "waitfor"
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_blind_tsql(request):
    return check_risk_found(request, r"\bwaitfor\b.*?\b(delay|time(out)?)\b", VERY_LOW_RISK)










