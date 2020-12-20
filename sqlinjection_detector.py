import re
from risk_level import RiskLevel
from sqlinjection_info import SqlInjectionInfo
BETWEEN_LEN = 7
AND_LEN = 3


def detector(request):
    """this is the main function of the library, in the proxy server you just need to run it over every request
    packet that reach the server
    :param request: the request that goes into the server
    :type request: string
    :return the dangerous level of the packet, according the list we define and the information about the attack
    :rtype: integer, string"""
    dangerous_level = 0
    counter_finds = 0  # counter the number of function that detect the request
    counter = 0  # counter for the serial number of the each detect function
    attack_info = ""
    sqlInfo = SqlInjectionInfo()
    # the list of the premade function that detect sql injection we take from online
    list_of_detection_function = [find_master_access, check_user_disclosure, check_mongo_db_command,
                                  check_cstyle_comment, check_blind_benchmark, check_load_file_disclosure, check_load_data_disclosure,
                                  check_write_into_outfile, check_blind_sql_sleep, check_concat_command, check_information_disclosure,
                                  check_sleep_pg_command, check_blind_tsql,
                                  check_substr_command, check_user_command, check_version_command,
                                  check_system_variable, check_if_command, check_ifnull_command, check_case_command, check_exec_command,
                                  check_create_command, check_user_info_disclosure, check_db_info_disclosure,
                                  check_shadow_info_disclosure, check_db_command]
    for detect_sql_function in list_of_detection_function:
        if detect_sql_function():
            sqlInfo.set_attack_info(counter)
            counter_finds += 1
        counter += 1
    attack_info += sqlInfo.get_info()
    if counter_finds == 1:
        dangerous_level = RiskLevel.VERY_LOW_RISK
    elif counter_finds > 1 and counter_finds < 4:
        dangerous_level = RiskLevel.MEDIUM_RISK
    elif counter_finds >= 4:
        dangerous_level = RiskLevel.HIGH_RISK
    dangerous_level_custom, attack_info_custom = check_common_sql_commands(request)  # use the custom function and detection function we made
    if (dangerous_level + dangerous_level_custom) >= RiskLevel.LARGE_RISK:
        return attack_info + '\n' + attack_info_custom


def find_master_access(request):
    """check if the user try to run from the input SQLite information disclosure “sqlite_master”
    :param request: the request packet
    :type request: string
    :return: True if found, False if not
    :rtype boolean"""
    return True if re.search(r"\bsqlite_master\b", request) else False


def check_user_disclosure(request):
    """check if the user try to run from the input MySQL information disclosure “mysql.user”
    :param request: the request packet
    :type request: string
    :return: True if found, False if not
    :rtype boolean"""
    return True if re.search(r"\bmysql.*?\..*?user\b", request) else False


def check_mongo_db_command(request):
    """check if the user try to run from the input Common mongoDB commands
    :param request: the request packet
    :type request: string
    :return: True if found, False if not
    :rtype boolean"""
    return True if re.search(r"\[\$(ne|eq|lte?|gte?|n?in|mod|all|size|exists|type|slice|or)\]", request) else False


def check_cstyle_comment(request):
    """check if the user try to run from the input Common C-style comment
    :param request: the request packet
    :type request: string
    :return: True if found, False if not
    :rtype boolean"""
    return True if re.search(r" \/\*.*?\*\/", request) else False


def check_blind_benchmark(request):
    """check if the user try to run from the input blind sql benchmark
    :param request: the request packet
    :type request: string
    :return: True if found, False if not
    :rtype boolean"""
    return True if re.search(r"bbenchmark\b.*?\(.+?,.+?\)", request) else False


def check_blind_sql_sleep(request):
    """check if the user try to run from the input blind sql sleep
    :param request: the request packet
    :type request: string
    :return: True if found, False if not
    :rtype boolean"""
    return True if re.search(r"\bsleep\b.*?\(.+?\)", request) else False


def check_load_file_disclosure(request):
    """check if the user try to run from the input blind mysql disclosure "load_file"
    :param request: the request packet
    :type request: string
    :return: True if found, False if not
    :rtype boolean"""
    return True if re.search(r"\bload_file\b.*?\(.+?\)", request) else False


def check_load_data_disclosure(request):
    """check if the user try to run from the input blind mysql disclosure "load_data"
    :param request: the request packet
    :type request: string
    :return: True if found, False if not
    :rtype boolean"""
    return True if re.search(r"\bload\b.*?\bdata\b.*?\binfile\b.*?\binto\b.*?\btable\b", request) else False


def check_write_into_outfile(request):
    """check if the user try to run from the input MySQL file write "into outfile"
    :param request: the request packet
    :type request: string
    :return: True if found, False if not
    :rtype boolean"""
    return True if re.search(r"\bselect\b.*?\binto\b.*?\b(out|dump)file\b", request) else False


def check_concat_command(request):
    """check if the user try to run from the input the command concat
    :param request: the request packet
    :type request: string
    :return: True if found, False if not
    :rtype boolean"""
    return True if re.search(r"\b(group_)?concat(_ws)?\b.*?\(.+?\)", request) else False


def check_information_disclosure(request):
    """check if the user try to run from the input mysql information disclosure
    :param request: the request packet
    :type request: string
    :return: True if found, False if not
    :rtype boolean"""
    return True if re.search(r"\binformation_schema\b", request) else False


def check_sleep_pg_command(request):
    """check if the user try to run from input the pgsql sleep command
    :param request: the request packet
    :type request: string
    :return: True if found, False if not
    :rtype boolean"""
    return True if re.search(request, r"\bpg_sleep\b.*?\(.+?\)") else False


def check_blind_tsql(request):
    """check if the user try to run from input the blind tsql "waitfor"
    :param request: the request packet
    :type request: string
    :return: True if found, False if not
    :rtype boolean"""
    return True if re.search(r"\bwaitfor\b.*?\b(delay|time(out)?)\b", request) else False


def check_substr_command(request):
    """check if the user try to run from input the SQL substr command
    :param request: the request packet
    :type request: string
    :return: True if found, False if not
    :rtype boolean"""
    return True if re.search(r"\bsubstr(ing(_index)?)?\b.*?\(.+?,.+?\)", request) else False


def check_user_command(request):
    """check if the user try to run from input the SQL user command
    :param request: the request packet
    :type request: string
    :return: True if found, False if not
    :rtype boolean"""
    return True if re.search(r"\b(current_)?user\b.*?\(.*?\)", request) else False


def check_version_command(request):
    """check if the user try to run from input the SQL version command
    :param request: the request packet
    :type request: string
    :return: True if found, False if not
    :rtype boolean"""
    return True if re.search(r" \bversion\b.*?\(.*?\)", request) else False


def check_system_variable(request):
    """check if the user try to run from input the SQL system variable command
    :param request: the request packet
    :type request: string
    :return: True if found, False if not
    :rtype boolean"""
    return True if re.search(r"@@.+?", request) else False


def check_if_command(request):
    """check if the user try to run from input the SQL if command
    :param request: the request packet
    :type request: string
    :return: True if found, False if not
    :rtype boolean"""
    return True if re.search(r"\bif\b.*?\(.+?,.+?,.+?\)", request) else False


def check_ifnull_command(request):
    """check if the user try to run from input the SQL ifnull command
    :param request: the request packet
    :type request: string
    :return: True if found, False if not
    :rtype boolean"""
    return True if re.search(request, r"\b(ifnull|nullif)\b.*?\(.+?,.+?\)") else False


def check_case_command(request):
    """check if the user try to run from input the SQL case command
    :param request: the request packet
    :type request: string
    :return: True if found, False if not
    :rtype boolean"""
    return True if re.search(r"\bcase\b.+?\bwhen\b.+?\bend\b", request) else False


def check_exec_command(request):
    """check if the user try to run from input the MSSQL exec command
    :param request: the request packet
    :type request: string
    :return: True if found, False if not
    :rtype boolean"""
    return True if re.search(r"\bexec\b.+?\bxp_cmdshell\b", request) else False


def check_create_command(request):
    """check if the user try to run from input the SQL create command
    :param request: the request packet
    :type request: string
    :return: True if found, False if not
    :rtype boolean"""
    return True if re.search(r"\bcreate\b.+?\b(procedure|function)\b.*?\(.*?\)", request) else False


def check_user_info_disclosure(request):
    """check if the user try to run from input the PgSQL information disclosure “pg_user”
    :param request: the request packet
    :type request: string
    :return: True if found, False if not
    :rtype boolean"""
    return True if re.search(r"\bpg_user\b", request) else False


def check_db_info_disclosure(request):
    """check if the user try to run from input the PgSQL information disclosure “pg_database”
    :param request: the request packet
    :type request: string
    :return: True if found, False if not
    :rtype boolean"""
    return True if re.search(r"\bpg_database\b", request) else False


def check_shadow_info_disclosure(request):
    """check if the user try to run from input the PgSQL information disclosure “pg_shadow”
    :param request: the request packet
    :type request: string
    :return: True if found, False if not
    :rtype boolean"""
    return True if re.search(r"\bpg_shadow\b", request) else False


def check_db_command(request):
    """check if the user try to run from input the DATABASE command
    :param request: the request packet
    :type request: string
    :return: True if found, False if not
    :rtype boolean"""
    return True if re.search(r"\b(current_)?database\b.*?\(.*?\)", request) else False


def check_or_custom(logic_statement):
    """function check the or custom, and if its true, and return the dangerous level of the query
    :param logic_statement: the logical statement in the or
    :type logic_statement: string
    :return: the dangerous level
    :rtype: integer"""
    dangerous_level = 0
    if logic_statement:
        statement = logic_statement.group("statement")
        not_count = statement.count("not")
        statement = statement.replace("not", "")
        is_positive = False
        if not_count % 2 == 0:
            is_positive = True
        if logic_statement.group("operators"):
            if re.search(r"""\b=\b""", statement):
                statement = statement.replace('=', "==")
            elif "<>" in statement:
                statement = statement.replace("<>", "!=")
        elif logic_statement.group("like"):
            statement = statement.replace("like", "==")
        elif logic_statement.group("betweenand"):
            middle_value = statement[:statement.find("between")]
            lower_value = statement[statement.find("between") + BETWEEN_LEN: statement.find("and")]
            higher_value = statement[statement.find("and") + AND_LEN:]
            statement = lower_value + " <= " + middle_value + " <= " + higher_value
        try:
            result = eval(statement)
            print(statement)
            if not is_positive:  # eval's result should be the opposite (True -> False | False -> True)
                result = not result
            if result:  # checks if the or statement returns true
                dangerous_level += RiskLevel.VERY_DANGEROUS
            else:
                dangerous_level = RiskLevel.HIGH_RISK
        except:  # means that the or statement is incorrect
            dangerous_level = RiskLevel.LOW_RISK
    return dangerous_level


def check_delete_custom(sub_statement):
    """function check if this is a delete statement, and return the dangerous level
    :param sub_statement: the statement
    :type sub_statement: string
    :return: the dangerous level of the query
    :rtype: boolean"""
    return True if re.search(r"""delete\s+.+?\s+from\s+.+""", sub_statement) else False


def check_comment_custom(request):
    """function check if there is a comment in the request
    :param request: the request
    :type request: string
    :return: the dangerous level
    :rtype: boolean"""
    match_list = re.findall(r""";\s*(?:#|--)""", request)
    return len([match for match in match_list if match != ''])


def check_create_custom(sub_statement):
    """function check if the query is a create sql statement
    :param sub_statement: the sub statement
    :type sub_statement: string
    :return: the dangerous level
    :rtype: boolean"""
    return True if re.search(r"""create\s+(?P<createinfo>database|table|index|(?:or\s+replace\s+)?view)\s+.+""", sub_statement) else False


def check_alter_custom(sub_statement):
    """function check if the query is a alter table sql statement
        :param sub_statement: the sub statement
        :type sub_statement: string
        :return: the dangerous level
        :rtype: boolean"""
    return True if re.search(r"""alter\s+table\s+.+?\s+(?:add|drop\s+column)\s+.+""", sub_statement) else False


def check_drop_custom(sub_statement):
    """function check if the query is a drop sql statement
        :param sub_statement: the sub statement
        :type sub_statement: string
        :return: the dangerous level
        :rtype: boolean"""
    return True if re.search(r"""drop\s+(?P<deleteinfo>database|index|table|view)\s+.+""", sub_statement) else False


def check_exist_custom(sub_statement):
    """function check if the query is a where sql statement
        :param sub_statement: the sub statement
        :type sub_statement: string
        :return: the dangerous level
        :rtype: boolean"""
    return True if re.search(r"""where\s+exists""", sub_statement) else False


def check_update_custom(sub_statement):
    """function check if the query is a update sql statement
        :param sub_statement: the sub statement
        :type sub_statement: string
        :return: the dangerous level
        :rtype: boolean"""
    return True if re.search(r"""update\s+.+?\s+set\s+.+""", sub_statement) else False


def check_truncate_custom(sub_statement):
    """function check if the query is a truncate table sql statement
        :param sub_statement: the sub statement
        :type sub_statement: string
        :return: the dangerous level
        :rtype: boolean"""
    return True if re.search(r"""truncate\s+table\s+.+""", sub_statement) else False


def check_insert_custom(sub_statement):
    """function check if the query is a insert into sql statement
        :param sub_statement: the sub statement
        :type sub_statement: string
        :return: the dangerous level
        :rtype: boolean"""
    return True if re.search(r"""insert\s+into\s+(?:'[^']+?'|\"[^\"]+?\"|\[[^\]]+?\]|\w+)(?:\s*\(.+?\)\s*|\s+)values\s*\(.+\)""", sub_statement) else False


def check_select_union_custom(sub_statement):
    """function check if the query is a select union sql statement
        :param sub_statement: the sub statement
        :type sub_statement: string
        :return: the dangerous level
        :rtype: boolean"""
    return True if re.search(r"""select\s+.+?\s+from\s+.+?\s+union(?:\s+all)?\s+select\s+.+?\s+from\s+.+""", sub_statement) else False


def check_select_into_custom(sub_statement):
    """function check if the query is a select into sql statement
        :param sub_statement: the sub statement
        :type sub_statement: string
        :return: the dangerous level
        :rtype: boolean"""
    return True if re.search(r"""select\s+.+?\s+into\s+.+?\s+from\s+.+""", sub_statement) else False


def check_select_from_custom(sub_statement):
    """function check if the query is a select from sql statement
        :param sub_statement: the sub statement
        :type sub_statement: string
        :return: the dangerous level
        :rtype: boolean"""
    return True if re.search(r"""select.+?from\s+.+""", sub_statement) else False


def check_grant_revoke_custom(sub_statement):
    """function check if the query is a grant or revoke sql statement
        :param sub_statement: the sub statement
        :type sub_statement: string
        :return: the dangerous level
        :rtype: boolean"""
    grant_revoke_statement = re.search(r"""(?:grant|revoke)(?P<permissions>.+?)on\s+.+?\s+(?:to|from)\s+.+?""", sub_statement)
    dangerous_level = 0
    if grant_revoke_statement:

        permissions_statement = grant_revoke_statement.group("permissions")
        permission_lst = re.findall(r"""(?:select|delete|insert|update|references|alter|all){1,7}""", permissions_statement)
        if len(permission_lst) > 0:
            if "all" in permission_lst:
                dangerous_level += RiskLevel.VERY_DANGEROUS
            else:
                if "select" in permission_lst:
                    dangerous_level += True
                if "delete" in permission_lst:
                    dangerous_level += RiskLevel.HIGH_RISK
                if "insert" in permission_lst:
                    dangerous_level += RiskLevel.HIGH_RISK
                if "update" in permission_lst:
                    dangerous_level += RiskLevel.HIGH_RISK
                if "references" in permission_lst:
                    dangerous_level += RiskLevel.LOW_RISK
                if "alter" in permission_lst:
                    dangerous_level += RiskLevel.HIGH_RISK
        if not dangerous_level:  # if its still zero make it LOW_RISK
            return RiskLevel.VERY_LOW_RISK
    return dangerous_level


def check_common_sql_commands(request):
    """function check the request if its a common sql injection
            the function call to all the custom function we create by our self
            :param request: the request
            :type request: string
            :return: the dangerous level
            :return: info about the findings
            :rtype: boolean
            :rtype: sqlInjectionInfo"""
    dangerous_level = 0
    add_to_dangerous = 0
    statements_list = []
    custom_detect_info = SqlInjectionInfo()
    dangerous_level += check_comment_custom(request)
    if ';' in request:
        statements_list = request.split(';')
    else:
        statements_list.append(request)
    if statements_list[-1] == '':
        statements_list = statements_list[:-1]
    for sub_statement in statements_list:  # for example if the request contains couple of queries like:
        #  or 1 = 1; drop table table_name
        sub_statement = sub_statement.strip()  # remove spaces from begin and end of the sub_statement
        # for every sub statement check if there is one of the queries of the list below
        for or_statement in sub_statement.split("or")[1:]:  # checks for every statement if its an 'or' statement
            logic_statement = re.search(r"""(?P<statement>(?:not\s+)*\s*(?P<operators>.+?<[^=>]+|[^=!<>]+=[^=]+|[^<]+?>[^=]+|.+?(?:==|<=|>=|!=|<>).+?)\s*|(?:not\s+)*.+?\s+(?:(?P<like>like\s+.+)|(?P<betweenand>between\s+.+?and\s+.+)|(?P<in>in\s*\(.+\))))""", or_statement)
            add_to_dangerous += check_or_custom(logic_statement)
        if add_to_dangerous:  # the check or custom find some threat
            dangerous_level += add_to_dangerous
            custom_detect_info.set_attack_info_custom("or_custom")
        if check_alter_custom(sub_statement):
            dangerous_level += RiskLevel.MEDIUM_RISK
            custom_detect_info.set_attack_info_custom("alter_custom")
        if check_delete_custom(sub_statement):
            dangerous_level += RiskLevel.MEDIUM_RISK
            custom_detect_info.set_attack_info_custom("delete_custom")
        if check_create_custom(sub_statement):
            dangerous_level += RiskLevel.MEDIUM_RISK
            custom_detect_info.set_attack_info_custom("create_custom")
        if check_exist_custom(sub_statement):
            dangerous_level += RiskLevel.LOW_RISK
            custom_detect_info.set_attack_info_custom("exist_custom")
        if check_update_custom(sub_statement):
            dangerous_level += RiskLevel.MEDIUM_RISK
            custom_detect_info.set_attack_info_custom("update_custom")
        if check_truncate_custom(sub_statement):
            dangerous_level += RiskLevel.MEDIUM_RISK
            custom_detect_info.set_attack_info_custom("truncate_custom")
        if check_insert_custom(sub_statement):
            dangerous_level += RiskLevel.MEDIUM_RISK
            custom_detect_info.set_attack_info_custom("insert_custom")
        # we don't want to multiply the dangerous level because select union statement is also simple select statement,
        # so we add some if statements
        if check_select_union_custom(sub_statement):
            dangerous_level += RiskLevel.LARGE_RISK
            custom_detect_info.set_attack_info_custom("select_union_custom")
        elif check_select_into_custom(sub_statement):
            dangerous_level += RiskLevel.LARGE_RISK
            custom_detect_info.set_attack_info_custom("select_into_custom")
        elif check_select_from_custom(sub_statement):
            dangerous_level += RiskLevel.VERY_LOW_RISK
            custom_detect_info.set_attack_info_custom("select_from_custom")
        dangerous_level += check_grant_revoke_custom(sub_statement)
        if check_drop_custom(sub_statement):
            dangerous_level += RiskLevel.HIGH_RISK
            custom_detect_info.set_attack_info_custom("drop_custom")
    return dangerous_level, custom_detect_info.get_info()
