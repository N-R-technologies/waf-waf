import re
from detective.toolbox import RiskLevels


class AdvancedChecks:
    @staticmethod
    def grant_revoke(request) -> RiskLevels:
        grant_revoke_statement = re.search(r"""(?:grant|revoke)(?P<permissions>.+?)on\s+.+?\s+(?:to|from)\s+.+?""", request)
        risk_level = 0
        if grant_revoke_statement is not None:
            permissions_statement = grant_revoke_statement.group("permissions")
            permission_lst = re.findall(r"""\b(?:select|delete|insert|update|references|alter|all)\b""",
                                        permissions_statement)
            if len(permission_lst) > 0:
                if "all" in permission_lst:
                    risk_level = RiskLevels.CATASTROPHIC
                else:
                    if "alter" in permission_lst:
                        risk_level = RiskLevels.CRITICAL
                    elif "delete" in permission_lst:
                        risk_level = RiskLevels.CRITICAL
                    elif "insert" in permission_lst:
                        risk_level = RiskLevels.CRITICAL
                    elif "update" in permission_lst:
                        risk_level = RiskLevels.CRITICAL
                    elif "references" in permission_lst:
                        risk_level = RiskLevels.SLIGHT
                    elif "select" in permission_lst:
                        risk_level = RiskLevels.SLIGHT
            if risk_level == RiskLevels.NO_RISK:
                return RiskLevels.NEGLIGIBLE
            return risk_level
        return RiskLevels.NO_RISK
