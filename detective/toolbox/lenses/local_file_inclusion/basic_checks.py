import re
from detective.toolbox.risk_levels import RiskLevels


class BasicChecks:
    @staticmethod
    def etc_files(request):
        """
        check if the user try to access sensitive files from the server, that
        are locate in etc path
        :param request: the request packet
        :type request: str
        :return: the dangerous level according the findings if found, zero if not
        :rtype: enum RiskLevels
        """
        return RiskLevels.CRITICAL if re.search(r"(\betc\b.*\bmotd\b)|(\betc\b.*\bgroup\b)|(\betc\b.*\bresolv\.conf\b)|(\betc\b.*\bmtab\b)|(\betc\b.*\binetd\.conf\b)|(\betc/httpd\b.*\blogs\b.*\bacces_log\b)|(\betc\b.*\bhttpd\b.*\blogs\b.*\berror_log\b)|    (\betc\b.* \bissue\b)|(\betc\b.*\bprofile\b)|(\betc\b.*\bpasswd\b)|(\betc\b.*\bshadow\b)", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def home_files(request):
        """
        check if the user try to access sensitive files from the server, that
        are locate in home path
        :param request: the request packet
        :type request: str
        :return: the dangerous level according the findings if found, zero if not
        :rtype: enum RiskLevels
        """
        return RiskLevels.CRITICAL if re.search(r"(\bhome\b.*\b\.bash_history\b)|(\bhome\b.*\b\.profile\b)", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def root_files(request):
        """
        check if the user try to access sensitive files from the server, that
        are locate in root path
        :param request: the request packet
        :type request: str
        :return: the dangerous level according the findings if found, zero if not
        :rtype: enum RiskLevels
        """
        return RiskLevels.CATASTROPHIC if re.search(r"(\broot\b.*\.bash_history\b)|(~.*\.bash_history\b)|(\broot\b.*\.profile\b)|(~.*\.profile\b)", request)\
            else RiskLevels.NO_RISK

    @staticmethod
    def proc_files(request):
        """
        check if the user try to access sensitive files from the server, that
        are locate in proc path
        :param request: the request packet
        :type request: str
        :return: the dangerous level according the findings if found, zero if not
        :rtype: enum RiskLevels
        """
        return RiskLevels.CRITICAL if re.search(r"(\bproc\b.*\bversion\b)|(\bproc\b.*\bnet\b.*\broute\b)|(\bproc\b.*\bnet\b.*\btcp\b)|(\bproc\b.*\bnet\b.*\budp\b)|(\bproc\b.*\bnet\b.*\bfib_trie\b)|(\bproc\b.*\bself\b.*\benviron\b)|(\bproc\b.*\bsched_debug\b)|(\bproc\b.*\bmounts\b)|(\bproc\b.*\bnet\b.*\barp\b)", request)\
            else RiskLevels.NO_RISK

    @staticmethod
    def var_files(request):
        """
        check if the user try to access sensitive files from the server, that
        are locate in var path
        :param request: the request packet
        :type request: str
        :return: the dangerous level according the findings if found, zero if not
        :rtype: enum RiskLevels
        """
        return RiskLevels.CRITICAL if re.search(r"(\bvar\b.*\blog\b.*\bdmessage\b)|(\bvar\b.*\bwww\b.*\blogs\b.*\baccess_log\b)|(\bvar\b.*\bwww\b.*\blogs\b.*\baccess\.log\b)|(\bvar\b.*\blog\b.*\bapache2\b.*\baccess_log\b)|(\bvar\b.*\blog\b.*\bapache\b.*\baccess\.log\b)|(\bvar\b.*\blog\b.*\bapache2\b.*\baccess\.log\b)|(\bvar\b.*\blog\b.*\baccess_log\b)|(\bvar\b.*\bmail\b.*\broot\b)|(\bvar\b.*\bspool\b.*\bcron\b.*\bcrontabs\b)", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def information_files(request):
        """
        check if the user try to access sensitive files from the server,
        that with them he can see a lot of useful information about the users and the system
        :param request: the request packet
        :type request: str
        :return: the dangerous level according the findings if found, zero if not
        :rtype: enum RiskLevels
        """
        return RiskLevels.CATASTROPHIC if re.search(r"(\b.htaccess\b)|(\bconfig.php\b)|(\bauthorized_keys\b)|(\bid_rsa\b)|(\bid_rsa.keystore\b)|(\bid_rsa.pub\b)|(\bknown_hosts\b)|(\busr\b.*\blocal\b.*\bapache\b.*\blogs\b.*\baccess_log\b)", request)\
            else RiskLevels.NO_RISK
