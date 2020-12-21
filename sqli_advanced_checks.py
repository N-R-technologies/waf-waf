import re
from risk_level import RiskLevel


class SqlIAdvancedCheck:
    @staticmethod
    def check_delete(sub_statement):
        """
        function check if this is a delete statement, and return the dangerous level
        :param sub_statement: the statement
        :type sub_statement: string
        :return: if its find
        :return: the risk level
        :rtype: boolean
        :rtype: integer
        """
        return (True, RiskLevel.MEDIUM_RISK) if re.search(r"""delete\s+.+?\s+from\s+.+""", sub_statement)\
            else (False, RiskLevel.NO_RISK)

    @staticmethod
    def check_create(sub_statement):
        """
        function check if the query is a create sql statement
        :param sub_statement: the sub statement
        :type sub_statement: string
        :return: if its find
        :return: the risk level
        :rtype: boolean
        :rtype: integer
        """
        return (True, RiskLevel.MEDIUM_RISK) if re.search(r"""create\s+(?P<createinfo>database|table|index|
        (?:or\s+replace\s+)?view)\s+.+""", sub_statement) else (False, RiskLevel.NO_RISK)

    @staticmethod
    def check_alter(sub_statement):
        """
        function check if the query is a alter table sql statement
        :param sub_statement: the sub statement
        :type sub_statement: string
        :return: if its find
        :return: the risk level
        :rtype: boolean
        :rtype: integer
        """
        return (True, RiskLevel.MEDIUM_RISK) if re.search(r"""alter\s+table\s+.+?\s+(?:add|drop\s+column)\s+.+""",
                                                        sub_statement) else (False, RiskLevel.NO_RISK)

    @staticmethod
    def check_drop(sub_statement):
        """
        function check if the query is a drop sql statement
        :param sub_statement: the sub statement
        :type sub_statement: string
        :return: if its find
        :return: the risk level
        :rtype: boolean
        :rtype: integer
            """
        return (True, RiskLevel.LARGE_RISK) if re.search(r"""drop\s+(?P<deleteinfo>database|index|table|view)\s+.+""",
                                                       sub_statement) else (False, RiskLevel.NO_RISK)

    @staticmethod
    def check_exist(sub_statement):
        """
        function check if the query is a where sql statement
        :param sub_statement: the sub statement
        :type sub_statement: string
        :return: if its find
        :return: the risk level
        :rtype: boolean
        :rtype: integer
        """
        return (True, RiskLevel.VERY_LITTLE_RISK) if re.search(r"""where\s+exists""", sub_statement) \
            else (False, RiskLevel.NO_RISK)

    @staticmethod
    def check_update(sub_statement):
        """
        function check if the query is a update sql statement
        :param sub_statement: the sub statement
        :type sub_statement: string
        :return: if its find
        :return: the risk level
        :rtype: boolean
        :rtype: integer
        """
        return (True, RiskLevel.MEDIUM_RISK) if re.search(r"""update\s+.+?\s+set\s+.+""", sub_statement) \
            else (False, RiskLevel.NO_RISK)

    @staticmethod
    def check_truncate(sub_statement):
        """
        function check if the query is a truncate table sql statement
        :param sub_statement: the sub statement
        :type sub_statement: string
        :return: if its find
        :return: the risk level
        :rtype: boolean
        :rtype: integer
        """
        return (True, RiskLevel.MEDIUM_RISK) if re.search(r"""truncate\s+table\s+.+""", sub_statement) \
            else (False, RiskLevel.NO_RISK)

    @staticmethod
    def check_insert(sub_statement):
        """
        function check if the query is a insert into sql statement
        :param sub_statement: the sub statement
        :type sub_statement: string
        :return: if its find
        :return: the risk level
        :rtype: boolean
        :rtype: integer
        """
        return (True, RiskLevel.MEDIUM_RISK) if re.search(
            r"""insert\s+into\s+(?:'[^']+?'|\"[^\"]+?\"|\[[^\]]+?\]|\w+)(?:\s*\(.+?\)\s*|\s+)values\s*\(.+\)""",
            sub_statement) else (False, RiskLevel.NO_RISK)

    @staticmethod
    def check_select_union(sub_statement):
        """function check if the query is a select union sql statement
        :param sub_statement: the sub statement
        :type sub_statement: string
        :return: if its find
        :return: the risk level
        :rtype: boolean
        :rtype: integer
        """
        return (True, RiskLevel.MEDIUM_RISK) if \
            re.search(r"""select\s+.+?\s+from\s+.+?\s+union(?:\s+all)?\s+select\s+.+?\s+from\s+.+""",
                      sub_statement) else (False, RiskLevel.NO_RISK)

    @staticmethod
    def check_select_into(sub_statement):
        """
        function check if the query is a select into sql statement
        :param sub_statement: the sub statement
        :type sub_statement: string
        :return: if its find
        :return: the risk level
        :rtype: boolean
        :rtype: integer
        """
        return (True, RiskLevel.MEDIUM_RISK) if re.search(r"""select\s+.+?\s+into\s+.+?\s+from\s+.+""", sub_statement) \
            else (False, RiskLevel.NO_RISK)

    @staticmethod
    def check_select_from(sub_statement):
        """
        function check if the query is a select from sql statement
        :param sub_statement: the sub statement
        :type sub_statement: string
        :return: if its find
        :return: the risk level
        :rtype: boolean
        :rtype: integer
        """
        return (True, RiskLevel.MEDIUM_RISK) if re.search(r"""select.+?from\s+.+""", sub_statement) \
            else (False, RiskLevel.NO_RISK)

    @staticmethod
    def check_grant_revoke(sub_statement):
        """
        function check if the query is a grant or revoke sql statement
        :param sub_statement: the sub statement
        :type sub_statement: string
        :return: if its find
        :return: the risk level
        :rtype: boolean
        :rtype: integer
        """
        grant_revoke_statement = re.search(r"""(?:grant|revoke)(?P<permissions>.+?)on\s+.+?\s+(?:to|from)\s+.+?""",
                                           sub_statement)
        risk_level = 0
        if grant_revoke_statement:

            permissions_statement = grant_revoke_statement.group("permissions")
            permission_lst = re.findall(r"""\b(?:select|delete|insert|update|references|alter|all)\b""",
                                        permissions_statement)
            if len(permission_lst) > 0:
                if "all" in permission_lst:
                    risk_level = RiskLevel.HIGH_RISK
                else:
                    if "alter" in permission_lst:
                        risk_level = RiskLevel.LARGE_RISK
                    elif "delete" in permission_lst:
                        risk_level = RiskLevel.LARGE_RISK
                    elif "insert" in permission_lst:
                        risk_level = RiskLevel.LARGE_RISK
                    elif "update" in permission_lst:
                        risk_level = RiskLevel.LARGE_RISK
                    elif "references" in permission_lst:
                        risk_level = RiskLevel.LOW_RISK
                    elif "select" in permission_lst:
                        risk_level = RiskLevel.LOW_RISK
            if not risk_level:  # if its still zero make it LOW_RISK
                return (True, RiskLevel.VERY_LITTLE_RISK)
            return (True, risk_level)
        return (False, RiskLevel.NO_RISK)

    @staticmethod
    def check_or(or_statement):
        """
        function check the or custom, and if its true, and return the risk level of the query
        :param logic_statement: the logical statement in the or
        :type logic_statement: string
        :return: if its find
        :return: the risk level
        :rtype: boolean
        :rtype: integer
        """
        risk_level = 0
        logic_statement = re.search(r"""(?P<statement>(?:not\s+)*\s*(?P<operators>.+?<[^=>]+|[^=!<>]+=[^=]+|[^<]
                    +?>[^=]+|.+?(?:==|<=|>=|!=|<>).+?)\s*|(?:not\s+)*.+?\s+(?:(?P<like>like\s+.+)|
                    (?P<betweenand>between\s+.+?and\s+.+)|(?P<in>in\s*\(.+\))))""", or_statement)
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
                lower_value = statement[statement.find("between") + len("between"): statement.find("and")]
                higher_value = statement[statement.find("and") + len("and"):]
                statement = lower_value + " <= " + middle_value + " <= " + higher_value
            try:
                result = eval(statement)
                print(statement)
                if not is_positive:  # eval's result should be the opposite (True -> False | False -> True)
                    result = not result
                if result:  # checks if the or statement returns true
                    risk_level = RiskLevel.LARGE_RISK
                else:
                    risk_level = RiskLevel.MEDIUM_RISK
            except:  # means that the or statement is incorrect
                risk_level = RiskLevel.VERY_LITTLE_RISK
            return (True, risk_level)
        return (False, RiskLevel.NO_RISK)
