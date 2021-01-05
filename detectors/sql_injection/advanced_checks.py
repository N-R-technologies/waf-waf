import re
from risk_level import RiskLevel


class AdvancedChecks:
    @staticmethod
    def grant_revoke(request):
        """
        function check if the query is a grant or revoke sql statement
        :param request: the sub statement
        :type request: string
        :return: the risk level
        :rtype: enum risk level
        """
        grant_revoke_statement = re.search(r"""(?:grant|revoke)(?P<permissions>.+?)on\s+.+?\s+(?:to|from)\s+.+?""", request)
        risk_level = 0
        if grant_revoke_statement is not None:
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
            if not risk_level:
                return RiskLevel.VERY_LITTLE_RISK
            return risk_level
        return RiskLevel.NO_RISK
