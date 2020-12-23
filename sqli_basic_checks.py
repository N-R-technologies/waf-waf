import re
from risk_level import RiskLevel


class SqlIBasicChecks:
    @staticmethod
    def find_in_set(request):
        """
        check if the user try to run from the input common MySQL function “find_in_set”
        :param request: the request packet
        :type request: integer
        :return: the risk level if found, zero if not
        :rtype: enum risk level
        """
        return RiskLevel.VERY_LITTLE_RISK if re.search(r"\bfind_in_set\b.*?\(.+?,.+?\)", request)\
            else RiskLevel.NO_RISK

    @staticmethod
    def master_access(request):
        """
        check if the user try to run from the input SQLite information disclosure “sqlite_master”
        :param request: the request packet
        :type request: integer
        :return: the risk level if found, zero if not
        :rtype: enum risk level
        """
        return RiskLevel.MEDIUM_RISK if re.search(r"\bsqlite_master\b", request) else RiskLevel.NO_RISK

    @staticmethod
    def user_disclosure(request):
        """
        check if the user try to run from the input MySQL information disclosure “mysql.user”
        :param request: the request packet
        :type request: integer
        :return: the risk level if found, zero if not
        :rtype: enum risk level
        """
        return RiskLevel.VERY_LITTLE_RISK if re.search(r"\bmysql.*?\..*?user\b", request) else RiskLevel.NO_RISK

    @staticmethod
    def mongo_db_command(request):
        """
        check if the user try to run from the input Common mongoDB commands
        :param request: the request packet
        :type request: integer
        :return: the risk level if found, zero if not
        :rtype: enum risk level
        """
        return RiskLevel.MEDIUM_RISK if \
            re.search(r"\[\$(ne|eq|lte?|gte?|n?in|mod|all|size|exists|type|slice|or)\]",request)\
            else RiskLevel.NO_RISK

    @staticmethod
    def cstyle_comment(request):
        """
        check if the user try to run from the input Common C-style comment
        :param request: the request packet
        :type request: integer
        :return: the risk level if found, zero if not
        :rtype: enum risk level
        """
        return RiskLevel.VERY_LITTLE_RISK if re.search(r" \/\*.*?\*\/", request) else RiskLevel.NO_RISK

    @staticmethod
    def blind_benchmark(request):
        """
        check if the user try to run from the input blind sql benchmark
        :param request: the request packet
        :type request: integer
        :return: the risk level if found, zero if not
        :rtype: enum risk level
        """
        return RiskLevel.MEDIUM_RISK if re.search(r"bbenchmark\b.*?\(.+?,.+?\)", request) else RiskLevel.NO_RISK

    @staticmethod
    def blind_sql_sleep(request):
        """
        check if the user try to run from the input blind sql sleep
        :param request: the request packet
        :type request: integer
        :return: the risk level if found, zero if not
        :rtype: enum risk level
        """
        return RiskLevel.LOW_RISK if re.search(r"\bsleep\b.*?\(.+?\)", request) else RiskLevel.NO_RISK

    @staticmethod
    def load_file_disclosure(request):
        """
        check if the user try to run from the input blind mysql disclosure "load_file"
        :param request: the request packet
        :type request: integer
        :return: the risk level if found, zero if not
        :rtype: enum risk level
        """
        return RiskLevel.MEDIUM_RISK if re.search(r"\bload_file\b.*?\(.+?\)", request) else RiskLevel.NO_RISK

    @staticmethod
    def load_data_disclosure(request):
        """
        check if the user try to run from the input blind mysql disclosure "load_data"
        :param request: the request packet
        :type request: integer
        :return: the risk level if found, zero if not
        :rtype: enum risk level
        """
        return RiskLevel.MEDIUM_RISK if re.search(r"\bload\b.*?\bdata\b.*?\binfile\b.*?\binto\b.*?\btable\b", request) \
            else RiskLevel.NO_RISK

    @staticmethod
    def write_into_outfile(request):
        """
        check if the user try to run from the input MySQL file write "into outfile"
        :param request: the request packet
        :type request: integer
        :return: the risk level if found, zero if not
        :rtype: enum risk level
        """
        return RiskLevel.MEDIUM_RISK if re.search(r"\bselect\b.*?\binto\b.*?\b(out|dump)file\b", request) \
            else RiskLevel.NO_RISK

    @staticmethod
    def concat_command(request):
        """
        check if the user try to run from the input the command concat
        :param request: the request packet
        :type request: integer
        :return: the risk level if found, zero if not
        :rtype: enum risk level
        """
        return RiskLevel.UNIMPORTANT_RISK if re.search(r"\b(group_)?concat(_ws)?\b.*?\(.+?\)", request) else RiskLevel.NO_RISK

    @staticmethod
    def information_disclosure(request):
        """
        check if the user try to run from the input mysql information disclosure
        :param request: the request packet
        :type request: integer
        :return: the risk level if found, zero if not
        :rtype: enum risk level
        """
        return RiskLevel.MEDIUM_RISK if re.search(r"\binformation_schema\b", request) else RiskLevel.NO_RISK

    @staticmethod
    def sleep_pg_command(request):
        """
        check if the user try to run from input the pgsql sleep command
        :param request: the request packet
        :type request: integer
        :return: the risk level if found, zero if not
        :rtype: enum risk level
        """
        return RiskLevel.LOW_RISK if re.search(request, r"\bpg_sleep\b.*?\(.+?\)") else RiskLevel.NO_RISK

    @staticmethod
    def blind_tsql(request):
        """
        check if the user try to run from input the blind tsql "waitfor"
        :param request: the request packet
        :type request: integer
        :return: the risk level if found, zero if not
        :rtype: enum risk level
        """
        return RiskLevel.LOW_RISK if re.search(r"\bwaitfor\b.*?\b(delay|time(out)?)\b", request) \
            else RiskLevel.NO_RISK

    @staticmethod
    def length_command(request):
        """
        check if the user try to run from input the mysql length command
        :param request: the request packet
        :type request: integer
        :return: the risk level if found, zero if not
        :rtype: enum risk level
        r"""
        return RiskLevel.UNIMPORTANT_RISK if re.search(request, r"\b(char_|bit_)?length\b.*?\(.+?\)")\
            else RiskLevel.NO_RISK

    @staticmethod
    def hex_command(request):
        """
        check if the user try to run from input the mysql hex/unhex command
        :param request: the request packet
        :type request: integer
        :return: the risk level if found, zero if not
        :rtype: enum risk level
        """
        return RiskLevel.UNIMPORTANT_RISK if re.search(r"\b(un)?hex\b.*?\(.+?\)", request) else RiskLevel.NO_RISK

    @staticmethod
    def base64_command(request):
        """
        check if the user try to run from input the mysql to base 64/ from base 64 command
        :param request: the request packet
        :type request: integer
        :return: the risk level if found, zero if not
        :rtype: enum risk level
        """
        return RiskLevel.UNIMPORTANT_RISK if re.search(r"\b(from|to)_base64\b.*?\(.+?\)", request) \
            else RiskLevel.NO_RISK

    @staticmethod
    def substr_command(request):
        """
        check if the user try to run from input the SQL substr command
        :param request: the request packet
        :type request: integer
        :return: the risk level if found, zero if not
        :rtype: enum risk level
        """
        return RiskLevel.UNIMPORTANT_RISK if re.search(r"\bsubstr(ing(_index)?)?\b.*?\(.+?,.+?\)", request) \
            else RiskLevel.NO_RISK

    @staticmethod
    def user_command(request):
        """
        check if the user try to run from input the SQL user command
        :param request: the request packet
        :type request: integer
        :return: the risk level if found, zero if not
        :rtype: enum risk level
        """
        return RiskLevel.LARGE_RISK if re.search(r"\b(current_)?user\b.*?\(.*?\)", request) else RiskLevel.NO_RISK

    @staticmethod
    def version_command(request):
        """
        check if the user try to run from input the SQL version command
        :param request: the request packet
        :type request: integer
        :return: the risk level if found, zero if not
        :rtype: enum risk level
        """
        return RiskLevel.LOW_RISK if re.search(r" \bversion\b.*?\(.*?\)", request) else RiskLevel.NO_RISK

    @staticmethod
    def system_variable(request):
        """
        check if the user try to run from input the SQL system variable command
        :param request: the request packet
        :type request: integer
        :return: the risk level if found, zero if not
        :rtype: enum risk level
        """
        return RiskLevel.LOW_RISK if re.search(r"@@.+?", request) else RiskLevel.NO_RISK

    @staticmethod
    def oct_command(request):
        """
        check if the user try to run from input the SQL oct command
        :param request: the request packet
        :type request: integer
        :return: the risk level if found, zero if not
        :rtype: enum risk level
        """
        return RiskLevel.UNIMPORTANT_RISK if re.search(r"\boct\b.*?\(.+?\)", request) else RiskLevel.NO_RISK

    @staticmethod
    def ord_command(request):
        """
        check if the user try to run from input the SQL ord command
        :param request: the request packet
        :type request: integer
        :return: the risk level if found, zero if not
        :rtype: enum risk level
        """
        return RiskLevel.UNIMPORTANT_RISK if re.search(r"\bord\b.*?\(.+?\)", request) else RiskLevel.NO_RISK

    @staticmethod
    def ascii_command(request):
        """
        check if the user try to run from input the SQL ascii command
        :param request: the request packet
        :type request: integer
        :return: the risk level if found, zero if not
        :rtype: enum risk level
        """
        return RiskLevel.UNIMPORTANT_RISK if re.search(r"\bascii\b.*?\(.+?\)", request) else RiskLevel.NO_RISK

    @staticmethod
    def bin_command(request):
        """
        check if the user try to run from input the SQL bin command
        :param request: the request packet
        :type request: integer
        :return: the risk level if found, zero if not
        :rtype: enum risk level
        """
        return RiskLevel.UNIMPORTANT_RISK if re.search(r"\bbin\b.*?\(.+?\)", request) else RiskLevel.NO_RISK

    @staticmethod
    def char_command(request):
        """
        check if the user try to run from input the SQL char command
        :param request: the request packet
        :type request: integer
        :return: the risk level if found, zero if not
        :rtype: enum risk level
        """
        return RiskLevel.UNIMPORTANT_RISK if re.search(r"\bcha?r\b.*?\(.+?\)", request) else RiskLevel.NO_RISK

    @staticmethod
    def if_command(request):
        """
        check if the user try to run from input the SQL if command
        :param request: the request packet
        :type request: integer
        :return: the risk level if found, zero if not
        :rtype: enum risk level"""
        return RiskLevel.VERY_LITTLE_RISK if re.search(r"\bif\b.*?\(.+?,.+?,.+?\)", request) else \
            RiskLevel.NO_RISK

    @staticmethod
    def ifnull_command(request):
        """check if the user try to run from input the SQL ifnull command
        :param request: the request packet
        :type request: integer
        :return: the risk level if found, zero if not
        :rtype: enum risk level
        """
        return RiskLevel.VERY_LITTLE_RISK if re.search(request, r"\b(ifnull|nullif)\b.*?\(.+?,.+?\)") else \
            RiskLevel.NO_RISK

    @staticmethod
    def case_command(request):
        """
        check if the user try to run from input the SQL case command
        :param request: the request packet
        :type request: integer
        :return: the risk level if found, zero if not
        :rtype: enum risk level
        """
        return RiskLevel.VERY_LITTLE_RISK if re.search(r"\bcase\b.+?\bwhen\b.+?\bend\b", request) \
            else RiskLevel.NO_RISK

    @staticmethod
    def exec_command(request):
        """
        check if the user try to run from input the MSSQL exec command
        :param request: the request packet
        :type request: integer
        :return: the risk level if found, zero if not
        :rtype: enum risk level
        """
        return RiskLevel.HIGH_RISK if re.search(r"\bexec\b.+?\bxp_cmdshell\b", request) else RiskLevel.NO_RISK

    @staticmethod
    def create_command(request):
        """
        check if the user try to run from input the SQL create command
        :param request: the request packet
        :type request: integer
        :return: the risk level if found, zero if not
        :rtype: enum risk level
        """
        return RiskLevel.MEDIUM_RISK if re.search(r"\bcreate\b.+?\b(procedure|function)\b.*?\(.*?\)", request)\
            else RiskLevel.NO_RISK

    @staticmethod
    def user_info_disclosure(request):
        """
        check if the user try to run from input the PgSQL information disclosure “pg_user”
        :param request: the request packet
        :type request: integer
        :return: the risk level if found, zero if not
        :rtype: enum risk level
        """
        return RiskLevel.MEDIUM_RISK if re.search(r"\bpg_user\b", request) else RiskLevel.NO_RISK

    @staticmethod
    def db_info_disclosure(request):
        """
        check if the user try to run from input the PgSQL information disclosure “pg_database”
        :param request: the request packet
        :type request: integer
        :return: the risk level if found, zero if not
        :rtype: enum risk level
        """
        return RiskLevel.MEDIUM_RISK if re.search(r"\bpg_database\b", request) else RiskLevel.NO_RISK

    @staticmethod
    def shadow_info_disclosure(request):
        """
        check if the user try to run from input the PgSQL information disclosure “pg_shadow”
        :param request: the request packet
        :type request: integer
        :return: the risk level if found, zero if not
        :rtype: enum risk level
        """
        return RiskLevel.MEDIUM_RISK if re.search(r"\bpg_shadow\b", request) else RiskLevel.NO_RISK

    @staticmethod
    def db_command(request):
        """
        check if the user try to run from input the DATABASE command
        :param request: the request packet
        :type request: integer
        :return: the risk level if found, zero if not
        :rtype: enum risk level
        """
        return RiskLevel.UNIMPORTANT_RISK if re.search(r"\b(current_)?database\b.*?\(.*?\)", request) \
            else RiskLevel.NO_RISK

    @staticmethod
    def delete(request):
        """
        function check if this is a delete statement, and return the dangerous level
        :param request: the request
        :type request: string
        :return: the risk level
        :rtype: enum risk level
        """
        return RiskLevel.MEDIUM_RISK if re.search(r"""delete\s+.+?\s+from\s+.+""", request) \
            else RiskLevel.NO_RISK

    @staticmethod
    def create(request):
        """
        function check if the query is a create sql statement
        :param request: the sub statement
        :type request: string
        :return: the risk level
        :rtype: enum risk level
        """
        return RiskLevel.MEDIUM_RISK if \
            re.search(r"""create\s+(?P<createinfo>database|table|index|(?:or\s+replace\s+)?view)\s+.+""", request) \
            else RiskLevel.NO_RISK

    @staticmethod
    def alter(request):
        """
        function check if the query is a alter table sql statement
        :param request: the sub statement
        :type request: string
        :return: the risk level
        :rtype: enum risk level
        """
        return RiskLevel.MEDIUM_RISK if re.search(r"""alter\s+table\s+.+?\s+(?:add|drop\s+column)\s+.+""",
                                                          request) else RiskLevel.NO_RISK

    @staticmethod
    def drop(request):
        """
        function check if the query is a drop sql statement
        :param request: the request
        :type request: string
        :return: the risk level
        :rtype: enum risk level
        """
        return RiskLevel.LARGE_RISK if re.search(r"""drop\s+(?P<deleteinfo>database|index|table|view)\s+.+""",
                                                         request) else RiskLevel.NO_RISK

    @staticmethod
    def exist(request):
        """
        function check if the query is a where sql statement
        :param request: the request
        :type request: string
        :return: the risk level
        :rtype: enum risk level
        """
        return RiskLevel.VERY_LITTLE_RISK if re.search(r"""where\s+exists""", request) \
            else RiskLevel.NO_RISK

    @staticmethod
    def update(request):
        """
        function check if the query is a update sql statement
        :param request: the request
        :type request: string
        :return: the risk level
        :rtype: enum risk level
        """
        return RiskLevel.MEDIUM_RISK if re.search(r"""update\s+.+?\s+set\s+.+""", request) \
            else RiskLevel.NO_RISK

    @staticmethod
    def truncate(request):
        """
        function check if the query is a truncate table sql statement
        :param request: the request
        :type request: string
        :return: the risk level
        :rtype: enum risk level
        """
        return RiskLevel.MEDIUM_RISK if re.search(r"""truncate\s+table\s+.+""", request) \
            else RiskLevel.NO_RISK

    @staticmethod
    def insert(request):
        """
        function check if the query is a insert into sql statement
        :param request: the request
        :type request: string
        :return: the risk level
        :rtype: enum risk level
        """
        return RiskLevel.MEDIUM_RISK if re.search(
            r"""insert\s+into\s+(?:'[^']+?'|\"[^\"]+?\"|\[[^\]]+?\]|\w+)(?:\s*\(.+?\)\s*|\s+)values\s*\(.+\)""",
            request) else RiskLevel.NO_RISK

    @staticmethod
    def select_union(request):
        """
        function check if the query is a select union sql statement
        :param request: the request
        :type request: string
        :return: the risk level
        :rtype: enum risk level
        """
        return RiskLevel.MEDIUM_RISK if \
            re.search(r"""select\s+.+?\s+from\s+.+?\s+union(?:\s+all)?\s+select\s+.+?\s+from\s+.+""",
                      request) else RiskLevel.NO_RISK

    @staticmethod
    def select_into(request):
        """
        function check if the query is a select into sql statement
        :param request: the request
        :type request: string
        :return: the risk level
        :rtype: enum risk level
        """
        return (True, RiskLevel.MEDIUM_RISK) if re.search(r"""select\s+.+?\s+into\s+.+?\s+from\s+.+""", request) \
            else RiskLevel.NO_RISK

    @staticmethod
    def select_from(request):
        """
        function check if the query is a select from sql statement
        :param request: the request
        :type request: string
        :return: the risk level
        :rtype: enum risk level
        """
        return RiskLevel.MEDIUM_RISK if re.search(r"""select.+?from\s+.+""", request) \
            else RiskLevel.NO_RISK

    @staticmethod
    def or_statement(request):
        """
        function check the or custom, and if its true, and return the risk level of the query
        :param request: the request
        :type request: string
        :return: the risk level
        :rtype: enum risk level
        """
        return RiskLevel.LOW_RISK if \
            re.search(r"""or(?P<statement>(?:not\s+)*\s*(?P<operators>.+?<[^=>]+|[^=!<>]+=[^=]+|[^<]+?>[^=]+|.+?(?:==|<=|>=|!=|<>).+?)\s*|(?:not\s+)*.+?\s+(?:(?P<like>like\s+.+)|(?P<betweenand>between\s+.+?and\s+.+)|(?P<in>in\s*\(.+\))))""", request) \
            else RiskLevel.NO_RISK

