import re
from detective.toolbox import RiskLevels


class BasicChecks:
    @staticmethod
    def etc_files(request) -> RiskLevels:
        return RiskLevels.CRITICAL \
            if re.search(r"""(\betc\b.*\bmotd\b)|(\betc\b.*\bgroup\b)|(\betc\b.*\bresolv\.conf\b)|(\betc\b.*\bmtab\b)|(\betc\b.*\binetd\.conf\b)|(\betc/httpd\b.*\blogs\b.*\bacces_log\b)|(\betc\b.*\bhttpd\b.*\blogs\b.*\berror_log\b)|    (\betc\b.* \bissue\b)|(\betc\b.*\bprofile\b)|(\betc\b.*\bpasswd\b)|(\betc\b.*\bshadow\b)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def home_files(request) -> RiskLevels:
        return RiskLevels.CRITICAL \
            if re.search(r"""(\bhome\b.*\b\.bash_history\b)|(\bhome\b.*\b\.profile\b)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def root_files(request) -> RiskLevels:
        return RiskLevels.CATASTROPHIC \
            if re.search(r"""(\broot\b.*\.bash_history\b)|(~.*\.bash_history\b)|(\broot\b.*\.profile\b)|(~.*\.profile\b)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def proc_files(request) -> RiskLevels:
        return RiskLevels.CRITICAL \
            if re.search(r"""(\bproc\b.*\bversion\b)|(\bproc\b.*\bnet\b.*\broute\b)|(\bproc\b.*\bnet\b.*\btcp\b)|(\bproc\b.*\bnet\b.*\budp\b)|(\bproc\b.*\bnet\b.*\bfib_trie\b)|(\bproc\b.*\bself\b.*\benviron\b)|(\bproc\b.*\bsched_debug\b)|(\bproc\b.*\bmounts\b)|(\bproc\b.*\bnet\b.*\barp\b)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def var_files(request) -> RiskLevels:
        return RiskLevels.CRITICAL \
            if re.search(r"""(\bvar\b.*\blog\b.*\bdmessage\b)|(\bvar\b.*\bwww\b.*\blogs\b.*\baccess_log\b)|(\bvar\b.*\bwww\b.*\blogs\b.*\baccess\.log\b)|(\bvar\b.*\blog\b.*\bapache2\b.*\baccess_log\b)|(\bvar\b.*\blog\b.*\bapache\b.*\baccess\.log\b)|(\bvar\b.*\blog\b.*\bapache2\b.*\baccess\.log\b)|(\bvar\b.*\blog\b.*\baccess_log\b)|(\bvar\b.*\bmail\b.*\broot\b)|(\bvar\b.*\bspool\b.*\bcron\b.*\bcrontabs\b)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def information_files(request) -> RiskLevels:
        return RiskLevels.CATASTROPHIC \
            if re.search(r"""(\b\.htaccess\b)|(\bconfig\.php\b)|(\bauthorized_keys\b)|(\bid_rsa\b)|(\bid_rsa\.keystore\b)|(\bid_rsa\.pub\b)|(\bknown_hosts\b)|(\busr\b.*\blocal\b.*\bapache\b.*\blogs\b.*\baccess_log\b)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def windows_files(request) -> RiskLevels:
        return RiskLevels.CRITICAL \
            if re.search(r"""(\bc:.*\bwindows\b.*\bwin\.ini\b)|(\bc:.*\bwindows\b.*\brepair\b.*\bsam\b)|(\bc:.*\bwindows\b.*\bphp\.ini\b)|(\bc:.*\bwindows\b.*\btemp\b)|(\bwindows\b.*\brepair\b.*sam\b)|(\bwindows\b.*\bsystem32\b.*\bconfig\b.*\bregback\b.*\bsam\b)|(\bwindows\b.*\bsystem32\b.*\bconfig\b.*\bsam\b)|(\bwindows\b.*\brepair\b.*\bsystem\b)|(\bwindows\b.*\bsystem32\b.*\bconfig\b.*\bsystem\b)|(\bwindows\b.*\bsystem32\b.*\bconfig\b.*\bregback\b.*\bsystem\b)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def sensitive_windows_files(request) -> RiskLevels:
        return RiskLevels.CATASTROPHIC \
            if re.search(r"""(\bc:.*\bboot\.ini\b)|(\bc:.*\bwinint\b.*\bwin\.ini\b)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def program_files(request) -> RiskLevels:
        return RiskLevels.CRITICAL \
            if re.search(r"""(\bc:.*\bprogram files\b.*apache group\b.*apache\b.*conf\bhttpd\.conf\b)|(\bc:.*\bprogram files\b.*\bapache group\b.*\bapache2\bconf\b.*httpd\.conf\b)|(\bc:.*\bprogram files\b.*\bxampp\b.*\bapache\b.*\bconf\b.*\bhttpd\.conf\b)|(\bc:.*\bprogram files\b.*\bapache group\b.*\bapache\b.*\blogs\b.*\baccess\.log\b)|(\bc:.*\bprogram files\b.*\bapache group\b.*\bapache\b.*\blogs\b.*\berror\.log\b)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def windows_variables(request) -> RiskLevels:
        return RiskLevels.SLIGHT \
            if re.search(r"""%(home(drive|path)|system(drive|root)|windir|user(domain|profile|name)|((local)?app|program)data)%""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def php_files(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""(\bc:.*\bwinint\b.*\bphp\.ini\b)|(\bc:.*\bphp\b.*\bphp\.ini\b)|(\bc:.*\bphp5\b.*\bphp\.ini\b)|(\bc:.*\bphp4\b.*\bphp\.ini\b)|(\bc:.*\bapache\b.*\bphp\b.*\bphp\.ini\b)|(\bc:.*\bxampp\b.*\bapache\b.*\bbin\b.*\bphp\.ini\b)|(\bc:.*\bhome2\b.*\bbin\b.*\bstable\b.*\bapache\b.*\bphp\.ini\b)|(\bc:.*\bhome\b.*\bbin\b.*\bstable\b.*\bapache\b.*\bphp\.ini\b)|(\bc:.*\bphp\b.*\bsessions\b)|(\bc:.*\bphp5\b.*\bsessions\b)|(\bc:.*\bphp4\b.*\bsessions\b)|(\bc:.*\bphp7\b.*\bsessions\b)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def php_functions(request) -> RiskLevels:
        return RiskLevels.CRITICAL if re.search(r"""\bf(get|open|read|write)\b.*?\(.+?\)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def php_expect_wrapper(request) -> RiskLevels:
        return RiskLevels.CRITICAL if re.search(r"""php\?.+?=\s*expect://.+?""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def php_file_get_put_content(request):
        return RiskLevels.CRITICAL if re.search(r"""\bfile_(get|put)_contents\b.*?\(.+?\)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def php_edit_files_function(request) -> RiskLevels:
        return RiskLevels.CRITICAL \
            if re.search(r"""(\brequire(_once)?\b.*?;)|(\binclude(_once)?\b.*?;)|(\breadfile\b.*?\(.+?\);)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def php_stream_filter(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""php:\/\/filter""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def stream_filter_base64(request) -> RiskLevels:
        return RiskLevels.MODERATE if re.search(r"""convert\.base64-(de|en)code""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def stream_filter_zlib(request) -> RiskLevels:
        return RiskLevels.MODERATE if re.search(r"""zlib\.(de|in)flate""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def apache_server_side_inclusion(request) -> RiskLevels:
        return RiskLevels.CATASTROPHIC \
            if re.search(r"""<!--\W*?#\W*?(cmd|echo|exec|include|printenv)\b""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def url_encoding_unicode(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""%(c0\.|af\.|5c\.)|(%2e%2e[\/\\])|(%c0%ae[\/\\])""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def local_chrome_files(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""\b(chrome|file):\/\/""", request) \
            else RiskLevels.NO_RISK
