import re
from detective.toolbox import RiskLevels


class BasicChecks:
    @staticmethod
    def cstyle_comment(request) -> RiskLevels:
        return RiskLevels.NEGLIGIBLE if re.search(r"""/\*.*?\*/""", request) else RiskLevels.NO_RISK

    @staticmethod
    def find_in_set(request) -> RiskLevels:
        return RiskLevels.NEGLIGIBLE if re.search(r"""\bfind_in_set\b.*?\(.+?,.+?\)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def master_access(request) -> RiskLevels:
        return RiskLevels.MODERATE if re.search(r"""\bsqlite_master\b""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def user_disclosure(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""\bmysql.*?\..*?user\b""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def user_info_disclosure(request) -> RiskLevels:
        return RiskLevels.CRITICAL if re.search(r"""\bpg_user\b""", request) else RiskLevels.NO_RISK

    @staticmethod
    def db_info_disclosure(request) -> RiskLevels:
        return RiskLevels.MEDIUM_RISK if re.search(r"""\bpg_database\b""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def shadow_info_disclosure(request) -> RiskLevels:
        return RiskLevels.MEDIUM_RISK if re.search(r"""\bpg_shadow\b""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def load_file_disclosure(request) -> RiskLevels:
        return RiskLevels.MODERATE if re.search(r"""\bload_file\b.*?\(.+?\)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def load_data_disclosure(request) -> RiskLevels:
        return RiskLevels.MODERATE if re.search(r"""\bload\b.*?\bdata\b.*?\binfile\b.*?\binto\b.*?\btable\b""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def write_into_outfile(request) -> RiskLevels:
        return RiskLevels.MODERATE if re.search(r"""\bselect\b.*?\binto\b.*?\b(out|dump)file\b""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def information_disclosure(request) -> RiskLevels:
        return RiskLevels.MODERATE if re.search(r"""\binformation_schema\b""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def concat_command(request) -> RiskLevels:
        return RiskLevels.NEGLIGIBLE if re.search(r"""\b(group_)?concat(_ws)?\b.*?\(.+?\)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def blind_benchmark(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""bbenchmark\b.*?\(.+?,.+?\)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def blind_sql_sleep(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""\bsleep\b.*?\(.+?\)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def sleep_pg_command(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""\bpg_sleep\b.*?\(.+?\)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def blind_tsql(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""\bwaitfor\b.*?\b(delay|time(out)?)\b""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def length_command(request) -> RiskLevels:
        return RiskLevels.NEGLIGIBLE if re.search(r"""\b(char_|bit_)?length\b.*?\(.+?\)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def hex_command(request) -> RiskLevels:
        return RiskLevels.NEGLIGIBLE if re.search(r"""\b(un)?hex\b.*?\(.+?\)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def base64_command(request) -> RiskLevels:
        return RiskLevels.NEGLIGIBLE if re.search(r"""\b(from|to)_base64\b.*?\(.+?\)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def oct_command(request) -> RiskLevels:
        return RiskLevels.NEGLIGIBLE if re.search(r"""\boct\b.*?\(.+?\)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def ord_command(request) -> RiskLevels:
        return RiskLevels.NEGLIGIBLE if re.search(r"""\bord\b.*?\(.+?\)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def ascii_command(request) -> RiskLevels:
        return RiskLevels.NEGLIGIBLE if re.search(r"""\bascii\b.*?\(.+?\)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def bin_command(request) -> RiskLevels:
        return RiskLevels.NEGLIGIBLE if re.search(r"""\bbin\b.*?\(.+?\)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def char_command(request) -> RiskLevels:
        return RiskLevels.NEGLIGIBLE if re.search(r"""\bcha?r\b.*?\(.+?\)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def substr_command(request) -> RiskLevels:
        return RiskLevels.NEGLIGIBLE if re.search(r"""\bsubstr(ing(_index)?)?\b.*?\(.+?,.+?\)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def user_command(request) -> RiskLevels:
        return RiskLevels.CRITICAL if re.search(r"""\b(current_)?user\b.*?\(.*?\)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def version_command(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""@@version""", request) else RiskLevels.NO_RISK

    @staticmethod
    def system_variable(request) -> RiskLevels:
        return RiskLevels.NEGLIGIBLE if re.search(r"""@@.+?""", request) else RiskLevels.NO_RISK

    @staticmethod
    def if_command(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""\bif\b.*?\(.+?,.+?,.+?\)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def ifnull_command(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""\b(ifnull|nullif)\b.*?\(.+?,.+?\)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def case_command(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""\bcase\b.+?\bwhen\b.+?\bend\b""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def exec_command(request) -> RiskLevels:
        return RiskLevels.CATASTROPHIC if re.search(r"""\bexec\b.+?\bxp_cmdshell\b""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def create_command(request) -> RiskLevels:
        return RiskLevels.CRITICAL if re.search(r"""\bcreate\b.+?\b(procedure|function)\b.*?\(.*?\)""", request)\
            else RiskLevels.NO_RISK

    @staticmethod
    def mongo_db_command(request) -> RiskLevels:
        return RiskLevels.SLIGHT \
            if re.search(r"""\[\$(ne|eq|lte?|gte?|n?in|mod|all|size|exists|type|slice|or)\]""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def db_command(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""\b(current_)?database\b.*?\(.*?\)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def alter(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""alter\s+table\s+.+?\s+(?:add|drop\s+column)\s+.+""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def exist(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""where\s+exists""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def create(request) -> RiskLevels:
        return RiskLevels.CRITICAL \
            if re.search(r"""create\s+(?P<createinfo>database|table|index|(?:or\s+replace\s+)?view)\s+.+""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def update(request) -> RiskLevels:
        return RiskLevels.CRITICAL if re.search(r"""update\s+.+?\s+set\s+.+""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def delete(request) -> RiskLevels:
        return RiskLevels.CRITICAL if re.search(r"""delete\s+.+?\s+from\s+.+""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def drop(request) -> RiskLevels:
        return RiskLevels.CATASTROPHIC \
            if re.search(r"""drop\s+(?P<deleteinfo>database|index|table|view)\s+.+""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def truncate(request) -> RiskLevels:
        return RiskLevels.CRITICAL if re.search(r"""truncate\s+table\s+.+""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def insert(request) -> RiskLevels:
        return RiskLevels.CRITICAL \
            if re.search(r"""insert\s+into\s+(?:'[^']+?'|\"[^\"]+?\"|\[[^\]]+?\]|\w+)(?:\s*\(.+?\)\s*|\s+)values\s*\(.+\)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def select_union(request) -> RiskLevels:
        return RiskLevels.MODERATE if \
            re.search(r"""select\s+.+?\s+from\s+.+?\s+union(?:\s+all)?\s+select\s+.+?\s+from\s+.+""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def select_into(request) -> RiskLevels:
        return RiskLevels.MODERATE if re.search(r"""select\s+.+?\s+into\s+.+?\s+from\s+.+""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def select_from(request) -> RiskLevels:
        return RiskLevels.MODERATE if re.search(r"""select.+?from\s+.+""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def or_statement(request) -> RiskLevels:
        return RiskLevels.CRITICAL \
            if re.search(r"""\bor\b\s+(?P<statement>(?:not\s+)*(?P<operators>.+?<[^=>]+|[^=!<>]+=[^=]+|[^<]+?>[^=]+|.+?(?:==|<=|>=|!=|<>).+?)\s*|(?:not\s+)*.+?\s+(?:(?P<like>like\s+.+)|(?P<betweenand>between\s+.+?and\s+.+)|(?P<in>in\s*\(.+\))))""", request) \
            else RiskLevels.NO_RISK
