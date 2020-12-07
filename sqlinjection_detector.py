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
    return MEDIUM_RISK if re.search(r"\bfind_in_set\b.*?\(.+?,.+?\)", request) else NO_RISK


"""check if the user try to run from the input SQLite information disclosure “sqlite_master”
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def find_master_access(request):
    return LARGE_RISK if re.search(r"\bsqlite_master\b", request) else NO_RISK


"""check if the user try to run from the input MySQL information disclosure “mysql.user”
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_user_disclosure(request):
    return LITTLE_RISK if re.search(r"\bmysql.*?\..*?user\b", request) else NO_RISK


"""check if the user try to run from the input Common SQL command “union select”
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_union_select(request):
    return LITTLE_RISK if re.search(r"\bunion\b.+?\bselect\b", request) else NO_RISK


"""check if the user try to run from the input Common SQL command “update”
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_update_command(request):
    return LITTLE_RISK if re.search(r"\bupdate\b.+?\bset\b", request) else NO_RISK


"""check if the user try to run from the input Common SQL command “drop”
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_drop_command(request):
    return LITTLE_RISK if re.search(r"\bdrop\b.+?\b(database|table)\b", request) else NO_RISK


"""check if the user try to run from the input Common SQL command “delete”
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_delete_command(request):
    return LITTLE_RISK if re.search(r"\bdelete\b.+?\bfrom\b", request) else NO_RISK


"""check if the user try to run from the input Common SQL comment syntax
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_comment_syntax(request):
    return VERY_LITTLE_RISK if re.search(r"--.+?", request) else NO_RISK


"""check if the user try to run from the input Common mongoDB commands
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_mongo_db_command(request):
    return MEDIUM_RISK if re.search(r"\[\$(ne|eq|lte?|gte?|n?in|mod|all|size|exists|type|slice|or)\]", request) else NO_RISK


"""check if the user try to run from the input Common C-style comment
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_cstyle_comment(request):
    return LITTLE_RISK if re.search(r" \/\*.*?\*\/", request) else NO_RISK


"""check if the user try to run from the input blind sql benchmark
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_blind_benchmark(request):
    return MEDIUM_RISK if re.search(r"bbenchmark\b.*?\(.+?,.+?\)", request) else NO_RISK


"""check if the user try to run from the input blind sql sleep
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_blind_sql_sleep(request):
    return VERY_LITTLE_RISK if re.search(r"\bsleep\b.*?\(.+?\)", request) else NO_RISK


"""check if the user try to run from the input blind mysql disclosure "load_file"
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_load_file_disclosure(request):
    return LARGE_RISK if re.search(r"\bload_file\b.*?\(.+?\)", request) else NO_RISK


"""check if the user try to run from the input blind mysql disclosure "load_data"
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_load_data_disclosure(request):
    return LARGE_RISK if re.search(r"\bload\b.*?\bdata\b.*?\binfile\b.*?\binto\b.*?\btable\b", request) else NO_RISK


"""check if the user try to run from the input MySQL file write "into outfile"
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_write_into_outfile(request):
    return HIGH_RISK if re.search(r"\bselect\b.*?\binto\b.*?\b(out|dump)file\b", request) else NO_RISK


"""check if the user try to run from the input the command concat
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_concat_command(request):
    return LITTLE_RISK if re.search(r"\b(group_)?concat(_ws)?\b.*?\(.+?\)", request) else NO_RISK


"""check if the user try to run from the input mysql information disclosure
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_information_disclosure(request):
    return LARGE_RISK if re.search(r"\binformation_schema\b", request) else NO_RISK


"""check if the user try to run from input the pgsql sleep command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_sleep_pg_command(request):
    return MEDIUM_RISK if re.search(request, r"\bpg_sleep\b.*?\(.+?\)") else NO_RISK


"""check if the user try to run from input the blind tsql "waitfor"
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_blind_tsql(request):
    return VERY_LOW_RISK if re.search(r"\bwaitfor\b.*?\b(delay|time(out)?)\b", request) else NO_RISK


"""check if the user try to run from input the mysql length command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_length_command(request):
    return VERY_LITTLE_RISK if re.search(request, r"\b(char_|bit_)?length\b.*?\(.+?\)") else NO_RISK


"""check if the user try to run from input the mysql hex/unhex command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_hex_command(request):
    return VERY_LITTLE_RISK if re.search(r"\b(un)?hex\b.*?\(.+?\)", request) else NO_RISK


"""check if the user try to run from input the mysql to base 64/ from base 64 command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_base64_command(request):
    return VERY_LOW_RISK if re.search(r"\b(from|to)_base64\b.*?\(.+?\)", request) else NO_RISK


"""check if the user try to run from input the SQL substr command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_substr_command(request):
    return LITTLE_RISK if re.search(r"\bsubstr(ing(_index)?)?\b.*?\(.+?,.+?\)", request) else NO_RISK


"""check if the user try to run from input the SQL user command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_user_command(request):
    return VERY_LITTLE_RISK if re.search(r"\b(current_)?user\b.*?\(.*?\)", request) else NO_RISK


"""check if the user try to run from input the SQL version command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_version_command(request):
    return VERY_LITTLE_RISK if re.search(r" \bversion\b.*?\(.*?\)", request) else NO_RISK


"""check if the user try to run from input the SQL system variable command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_system_variable(request):
    return UNIMPORTANT_RISK if re.search(r"@@.+?", request) else NO_RISK


"""check if the user try to run from input the SQL oct command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_oct_command(request):
    return VERY_LITTLE_RISK if re.search(r"\boct\b.*?\(.+?\)", request) else NO_RISK


"""check if the user try to run from input the SQL ord command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_ord_command(request):
    return VERY_LITTLE_RISK if re.search(r"\bord\b.*?\(.+?\)", request) else NO_RISK


"""check if the user try to run from input the SQL ascii command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_ascii_command(request):
    return VERY_LITTLE_RISK if re.search(r" \bascii\b.*?\(.+?\)", request) else NO_RISK


"""check if the user try to run from input the SQL bin command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_bin_command(request):
    return VERY_LITTLE_RISK if re.search(r"\bbin\b.*?\(.+?\)", request) else NO_RISK


"""check if the user try to run from input the SQL char command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_char_command(request):
    return VERY_LITTLE_RISK if re.search(r"\bcha?r\b.*?\(.+?\)", request) else NO_RISK


"""check if the user try to run from input the SQL where command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_where_command(request):
    return VERY_LITTLE_RISK if re.search(r"\bwhere\b.+?(\b(not_)?(like|regexp)\b|[=<>])", request) else NO_RISK


"""check if the user try to run from input the SQL if command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_if_command(request):
    return VERY_LITTLE_RISK if re.search(r"\bif\b.*?\(.+?,.+?,.+?\)", request) else NO_RISK


"""check if the user try to run from input the SQL ifnull command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_ifnull_command(request):
    return LITTLE_RISK if re.search(request, r"\b(ifnull|nullif)\b.*?\(.+?,.+?\)") else NO_RISK


"""check if the user try to run from input the SQL where command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_where_condition_command(request):
    return LITTLE_RISK if re.search(r"\bwhere\b.+?(\b(n?and|x?or|not)\b|(\&\&|\|\|))", request) else NO_RISK


"""check if the user try to run from input the SQL case command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_case_command(request):
    return VERY_LOW_RISK if re.search(r"\bcase\b.+?\bwhen\b.+?\bend\b", request) else NO_RISK


"""check if the user try to run from input the MSSQL exec command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_exec_command(request):
    return VERY_DANGEROUS if re.search(r"\bexec\b.+?\bxp_cmdshell\b", request) else NO_RISK


"""check if the user try to run from input the SQL create command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_create_command(request):
    return VERY_LOW_RISK if re.search(r"\bcreate\b.+?\b(procedure|function)\b.*?\(.*?\)", request) else NO_RISK


"""check if the user try to run from input the SQL insert command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_insert_command(request):
    return LOW_RISK if re.search(r"\binsert\b.+?\binto\b.*?\bvalues\b.*?\(.+?\)", request) else NO_RISK


"""check if the user try to run from input the SQL insert command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_select_command(request):
    return LITTLE_RISK if re.search(r"\bselect\b.+?\bfrom\b", request) else NO_RISK


"""check if the user try to run from input the PgSQL information disclosure “pg_user”
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_user_info_disclosure(request):
    return LARGE_RISK if re.search(r"\bpg_user\b", request) else NO_RISK


"""check if the user try to run from input the PgSQL information disclosure “pg_database”
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_db_info_disclosure(request):
    return LARGE_RISK if re.search(r"\bpg_database\b", request) else NO_RISK


"""check if the user try to run from input the PgSQL information disclosure “pg_shadow”
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_shadow_info_disclosure(request):
    return LARGE_RISK if re.search(r"\bpg_shadow\b", request) else NO_RISK


"""check if the user try to run from input the DATABASE command
:param request: the request packet
:type request: integer
:return: the risk level if found, zero if not
:rtype integer"""


def check_db_command(request):
    return VERY_LITTLE_RISK if re.search(r"\b(current_)?database\b.*?\(.*?\)", request) else NO_RISK


def check_common_sql_commands(request):
    match_list = (re.findall(r"""('(''|[^'])*')|("(""|[^"])*")|(#$)|(--$)""", request))
    dangerous_level = 0
    operators_lst = ['>', '<', '=', 'LIKE', '>=', '<=']
    dangerous_level += len([match for match in match_list if match != ''])
    statements_list = []
    if ';' in request:
        statements_list = request.split(';')
    else:
        statements_list.append(request)
    if statements_list[-1] == '':
        statements_list = statements_list[:-1]
    for sql_statement in statements_list:
        sql_statement = sql_statement.strip()
        # check for every statement if its an or operator
        if re.search(r"""(\S+\s+\bor\b)\s+\S+((\s*([<=>]|<=|>=)\s*)|(\s+\blike\b\s+)|(\s+\bbetween\b\s+\S+\s+\band\b\s+))\S+""", sql_statement):
            finish_state = []
            sql_temp_statement = sql_statement
            for or_state in sql_temp_statement.split("or")[1:]:
                if 'like' in or_state or '=' in or_state:

                    or_state = or_state.replace('=', '==')
                    or_state = or_state.replace('like', '==')
                    finish_state.append(or_state)
                elif "between" in or_state:
                    middle_value = or_state[:or_state.find("between")]
                    lower_value = or_state[or_state.find("between")+6:or_state.find("and")]
                    higher_value = or_state[or_state.find("and")+3:]
                    finish_state.append("(" + middle_value + ">" + lower_value + ") " + "and " + "(" + middle_value + "<" + higher_value + ")")
                else:
                    finish_state.append(or_state)
            try:
                if eval("or".join(finish_state)):  # check if the or operator returns true
                    dangerous_level += 2
            except:  # means that the or statement is incorrect
                pass
        #  check the alter table command if exists in the sql statement
        elif re.search(r"""\balter\b\s+\btable\b\s+\S+\s+((\badd\b)|(\bdrop\b\s+\bcolumn\b))\s+\S+""", sql_statement):
            dangerous_level += 2





check_common_sql_commands('')
