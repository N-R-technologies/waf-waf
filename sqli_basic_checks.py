import re


class SqlIBasicCheck:
    @staticmethod
    def find_master_access(request):
        """
        check if the user try to run from the input SQLite information disclosure “sqlite_master”
        :param request: the request packet
        :type request: string
        :return: True if found, False if not
        :rtype boolean
        """
        return True if re.search(r"\bsqlite_master\b", request) else False

    @staticmethod
    def check_user_disclosure(request):
        """
        check if the user try to run from the input MySQL information disclosure “mysql.user”
        :param request: the request packet
        :type request: string
        :return: True if found, False if not
        :rtype boolean
        """
        return True if re.search(r"\bmysql.*?\..*?user\b", request) else False

    @staticmethod
    def check_mongo_db_command(request):
        """
        check if the user try to run from the input Common mongoDB commands
        :param request: the request packet
        :type request: string
        :return: True if found, False if not
        :rtype boolean
        """
        return True if re.search(r"\[\$(ne|eq|lte?|gte?|n?in|mod|all|size|exists|type|slice|or)\]", request) else False

    @staticmethod
    def check_cstyle_comment(request):
        """
        check if the user try to run from the input Common C-style comment
        :param request: the request packet
        :type request: string
        :return: True if found, False if not
        :rtype boolean
        """
        return True if re.search(r" \/\*.*?\*\/", request) else False

    @staticmethod
    def check_blind_benchmark(request):
        """
        check if the user try to run from the input blind sql benchmark
        :param request: the request packet
        :type request: string
        :return: True if found, False if not
        :rtype boolean
        """
        return True if re.search(r"bbenchmark\b.*?\(.+?,.+?\)", request) else False

    @staticmethod
    def check_blind_sql_sleep(request):
        """
        check if the user try to run from the input blind sql sleep
        :param request: the request packet
        :type request: string
        :return: True if found, False if not
        :rtype boolean
        """
        return True if re.search(r"\bsleep\b.*?\(.+?\)", request) else False

    @staticmethod
    def check_load_file_disclosure(request):
        """
        check if the user try to run from the input blind mysql disclosure "load_file"
        :param request: the request packet
        :type request: string
        :return: True if found, False if not
        :rtype boolean
        """
        return True if re.search(r"\bload_file\b.*?\(.+?\)", request) else False

    @staticmethod
    def check_load_data_disclosure(request):
        """
        check if the user try to run from the input blind mysql disclosure "load_data"
        :param request: the request packet
        :type request: string
        :return: True if found, False if not
        :rtype boolean
        """
        return True if re.search(r"\bload\b.*?\bdata\b.*?\binfile\b.*?\binto\b.*?\btable\b", request) else False

    @staticmethod
    def check_write_into_outfile(request):
        """
        check if the user try to run from the input MySQL file write "into outfile"
        :param request: the request packet
        :type request: string
        :return: True if found, False if not
        :rtype boolean
        """
        return True if re.search(r"\bselect\b.*?\binto\b.*?\b(out|dump)file\b", request) else False

    @staticmethod
    def check_concat_command(request):
        """
        check if the user try to run from the input the command concat
        :param request: the request packet
        :type request: string
        :return: True if found, False if not
        :rtype boolean
        """
        return True if re.search(r"\b(group_)?concat(_ws)?\b.*?\(.+?\)", request) else False

    @staticmethod
    def check_information_disclosure(request):
        """
        check if the user try to run from the input mysql information disclosure
        :param request: the request packet
        :type request: string
        :return: True if found, False if not
        :rtype boolean
        """
        return True if re.search(r"\binformation_schema\b", request) else False

    @staticmethod
    def check_sleep_pg_command(request):
        """
        check if the user try to run from input the pgsql sleep command
        :param request: the request packet
        :type request: string
        :return: True if found, False if not
        :rtype boolean
        """
        return True if re.search(request, r"\bpg_sleep\b.*?\(.+?\)") else False

    @staticmethod
    def check_blind_tsql(request):
        """
        check if the user try to run from input the blind tsql "waitfor"
        :param request: the request packet
        :type request: string
        :return: True if found, False if not
        :rtype boolean
        """
        return True if re.search(r"\bwaitfor\b.*?\b(delay|time(out)?)\b", request) else False

    @staticmethod
    def check_substr_command(request):
        """
        check if the user try to run from input the SQL substr command
        :param request: the request packet
        :type request: string
        :return: True if found, False if not
        :rtype boolean
        """
        return True if re.search(r"\bsubstr(ing(_index)?)?\b.*?\(.+?,.+?\)", request) else False

    @staticmethod
    def check_user_command(request):
        """
        check if the user try to run from input the SQL user command
        :param request: the request packet
        :type request: string
        :return: True if found, False if not
        :rtype boolean
        """
        return True if re.search(r"\b(current_)?user\b.*?\(.*?\)", request) else False

    @staticmethod
    def check_version_command(request):
        """
        check if the user try to run from input the SQL version command
        :param request: the request packet
        :type request: string
        :return: True if found, False if not
        :rtype boolean
        """
        return True if re.search(r" \bversion\b.*?\(.*?\)", request) else False

    @staticmethod
    def check_system_variable(request):
        """
        check if the user try to run from input the SQL system variable command
        :param request: the request packet
        :type request: string
        :return: True if found, False if not
        :rtype boolean
        """
        return True if re.search(r"@@.+?", request) else False

    @staticmethod
    def check_if_command(request):
        """
        check if the user try to run from input the SQL if command
        :param request: the request packet
        :type request: string
        :return: True if found, False if not
        :rtype boolean
        """
        return True if re.search(r"\bif\b.*?\(.+?,.+?,.+?\)", request) else False

    @staticmethod
    def check_ifnull_command(request):
        """
        check if the user try to run from input the SQL ifnull command
        :param request: the request packet
        :type request: string
        :return: True if found, False if not
        :rtype boolean
        """
        return True if re.search(request, r"\b(ifnull|nullif)\b.*?\(.+?,.+?\)") else False

    @staticmethod
    def check_case_command(request):
        """
        check if the user try to run from input the SQL case command
        :param request: the request packet
        :type request: string
        :return: True if found, False if not
        :rtype boolean
        """
        return True if re.search(r"\bcase\b.+?\bwhen\b.+?\bend\b", request) else False

    @staticmethod
    def check_exec_command(request):
        """
        check if the user try to run from input the MSSQL exec command
        :param request: the request packet
        :type request: string
        :return: True if found, False if not
        :rtype boolean
        """
        return True if re.search(r"\bexec\b.+?\bxp_cmdshell\b", request) else False

    @staticmethod
    def check_create_procedure_command(request):
        """
        check if the user try to run from input the SQL create command
        :param request: the request packet
        :type request: string
        :return: True if found, False if not
        :rtype boolean
        """
        return True if re.search(r"\bcreate\b.+?\b(procedure|function)\b.*?\(.*?\)", request) else False

    @staticmethod
    def check_user_info_disclosure(request):
        """
        check if the user try to run from input the PgSQL information disclosure “pg_user”
        :param request: the request packet
        :type request: string
        :return: True if found, False if not
        :rtype boolean
        """
        return True if re.search(r"\bpg_user\b", request) else False

    @staticmethod
    def check_db_info_disclosure(request):
        """
        check if the user try to run from input the PgSQL information disclosure “pg_database”
        :param request: the request packet
        :type request: string
        :return: True if found, False if not
        :rtype boolean
        """
        return True if re.search(r"\bpg_database\b", request) else False

    @staticmethod
    def check_shadow_info_disclosure(request):
        """
        check if the user try to run from input the PgSQL information disclosure “pg_shadow”
        :param request: the request packet
        :type request: string
        :return: True if found, False if not
        :rtype boolean
        """
        return True if re.search(r"\bpg_shadow\b", request) else False

    @staticmethod
    def check_db_command(request):
        """
        check if the user try to run from input the DATABASE command
        :param request: the request packet
        :type request: string
        :return: True if found, False if not
        :rtype boolean
        """
        return True if re.search(r"\b(current_)?database\b.*?\(.*?\)", request) else False