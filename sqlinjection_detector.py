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


"""check if the user try to run from input the mysql length command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_length_command(request):
    return check_risk_found(request, r"\b(char_|bit_)?length\b.*?\(.+?\)", VERY_LITTLE_RISK)


"""check if the user try to run from input the mysql hex/unhex command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_hex_command(request):
    return check_risk_found(request, r"\b(un)?hex\b.*?\(.+?\)", VERY_LITTLE_RISK)


"""check if the user try to run from input the mysql to base 64/ from base 64 command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_base64_command(request):
    return check_risk_found(request, r"\b(from|to)_base64\b.*?\(.+?\)", VERY_LOW_RISK)


"""check if the user try to run from input the SQL substr command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_substr_command(request):
    return check_risk_found(request, r"\bsubstr(ing(_index)?)?\b.*?\(.+?,.+?\)", LITTLE_RISK)


"""check if the user try to run from input the SQL user command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_user_command(request):
    return check_risk_found(request, r"\b(current_)?user\b.*?\(.*?\)", VERY_LITTLE_RISK)


"""check if the user try to run from input the SQL version command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_version_command(request):
    return check_risk_found(request, r" \bversion\b.*?\(.*?\)", VERY_LITTLE_RISK)


"""check if the user try to run from input the SQL system variable command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_system_variable(request):
    return check_risk_found(request, r"@@.+?", UNIMPORTANT_RISK)


"""check if the user try to run from input the SQL oct command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_oct_command(request):
    return check_risk_found(request, r"\boct\b.*?\(.+?\)", VERY_LITTLE_RISK)


"""check if the user try to run from input the SQL ord command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_ord_command(request):
    return check_risk_found(request, r"\bord\b.*?\(.+?\)", VERY_LITTLE_RISK)


"""check if the user try to run from input the SQL ascii command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_ascii_command(request):
    return check_risk_found(request, r" \bascii\b.*?\(.+?\)", VERY_LITTLE_RISK)


"""check if the user try to run from input the SQL bin command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_bin_command(request):
    return check_risk_found(request, r"\bbin\b.*?\(.+?\)", VERY_LITTLE_RISK)


"""check if the user try to run from input the SQL char command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_char_command(request):
    return check_risk_found(request, r"\bcha?r\b.*?\(.+?\)", VERY_LITTLE_RISK)


"""check if the user try to run from input the SQL where command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_where_command(request):
    return check_risk_found(request, r"\bwhere\b.+?(\b(not_)?(like|regexp)\b|[=<>])", VERY_LITTLE_RISK)


"""check if the user try to run from input the SQL if command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_if_command(request):
    return check_risk_found(request, r"\bif\b.*?\(.+?,.+?,.+?\)", VERY_LITTLE_RISK)


"""check if the user try to run from input the SQL ifnull command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_ifnull_command(request):
    return check_risk_found(request, r"\b(ifnull|nullif)\b.*?\(.+?,.+?\)", LITTLE_RISK)


"""check if the user try to run from input the SQL where command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_where_condition_command(request):
    return check_risk_found(request, r"\bwhere\b.+?(\b(n?and|x?or|not)\b|(\&\&|\|\|))", LITTLE_RISK)


"""check if the user try to run from input the SQL case command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_case_command(request):
    return check_risk_found(request, r"\bcase\b.+?\bwhen\b.+?\bend\b", VERY_LOW_RISK)


"""check if the user try to run from input the MSSQL exec command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_exec_command(request):
    return check_risk_found(request, r"\bexec\b.+?\bxp_cmdshell\b", VERY_DANGEROUS)


"""check if the user try to run from input the SQL create command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_create_command(request):
    return check_risk_found(request, r"\bcreate\b.+?\b(procedure|function)\b.*?\(.*?\)", VERY_LOW_RISK)


"""check if the user try to run from input the SQL insert command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_insert_command(request):
    return check_risk_found(request, r"\binsert\b.+?\binto\b.*?\bvalues\b.*?\(.+?\)", LOW_RISK)


"""check if the user try to run from input the SQL insert command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_select_command(request):
    return check_risk_found(request, r"\bselect\b.+?\bfrom\b", LITTLE_RISK)


"""check if the user try to run from input the PgSQL information disclosure “pg_user”
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_user_info_disclosure(request):
    return check_risk_found(request, r"\bpg_user\b", LARGE_RISK)


"""check if the user try to run from input the PgSQL information disclosure “pg_database”
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_db_info_disclosure(request):
    return check_risk_found(request, r"\bpg_database\b", LARGE_RISK)


"""check if the user try to run from input the PgSQL information disclosure “pg_shadow”
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_shadow_info_disclosure(request):
    return check_risk_found(request, r"\bpg_shadow\b", LARGE_RISK)


"""check if the user try to run from input the DATABASE command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_db_command(request):
    return check_risk_found(request, r"\b(current_)?database\b.*?\(.*?\)", VERY_LITTLE_RISK)