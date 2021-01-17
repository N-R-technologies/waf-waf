import re
from detective.toolbox.risk_levels import RiskLevels


class BasicChecks:
    @staticmethod
    def breaking_injections(request):
        """
        function Finds html breaking injections including whitespace attacks
        xss csrf
        """
        return RiskLevels.SLIGHT if \
            re.search(r"(?:\"[^\"]*[^-]?>)|(?:[^\w\s]\s*\\/>)|(?:>\")", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def breaking_injections(request):
        """
        function Finds attribute breaking injections including whitespace attacks
        xss csrf
        """
        return RiskLevels.SLIGHT if \
            re.search(r"(?:\"+.*[<=]\s*\"[^\"]+\")|(?:\"\s*\w+\s*=)|(?:>\w=\\/)|(?:#.+\)[\"\s]*>)|(?:\"\s*(?:src|style|on\w+)\s*=\s*\")|(?:[^\"]?\"[,;\s]+\w*[\[\(])",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def attribute_breaking(request):
        """
        function Finds unquoted attribute breaking injections
        xss csrf
        """
        return RiskLevels.NEGLIGIBLE if \
            re.search(r"(?:^>[\w\s]*<\\/?\w{2,}>)", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def name_JSON(request):
        """
        function Detects url-, name-, JSON, and referrer-contained payload attacks
        xss csrf
        """
        return RiskLevels.MODERATE if \
            re.search(r"(?:[+\\/]\s*name[\W\d]*[)+])|(?:;\W*url\s*=)|(?:[^\w\s\\/?:>]\s*(?:location|referrer|name)\s*[^\\/\w\s-])",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def xss_payload(request):
        """
        function Detects hash-contained xss payload attacks, setter usage and property overloading
        xss csrf
        """
        return RiskLevels.MODERATE if \
            re.search(r"(?:\W\s*hash\s*[^\w\s-])|(?:\w+=\W*[^,]*,[^\s(]\s*\()|(?:\?\"[^\s\"]\":)|(?:(?<!\\/)__[a-z]+__)|(?:(?:^|[\s)\]\}])(?:s|g)etter\s*=)",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def contained_xss(request):
        """
        function Detects self contained xss via with(), common loops and regex to string conversion
        xss csrf
        """
        return RiskLevels.MODERATE if \
            re.search(r"(?:with\s*\(\s*.+\s*\)\s*\w+\s*\()|(?:(?:do|while|for)\s*\([^)]*\)\s*\{)|(?:\\/[\w\s]*\[\W*\w)",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def with_ternary(request):
        """
        function Detects JavaScript with(), ternary operators and XML predicate attacks
        xss csrf
        """
        return RiskLevels.MODERATE if \
            re.search(r"(?:[=(].+\?.+:)|(?:with\([^)]*\)\))|(?:\.\s*source\W)", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def JavaScript_functions(request):
        """
        function Detects self-executing JavaScript functions
        xss csrf
        """
        return RiskLevels.MODERATE if \
            re.search(r"(?:\\/\w*\s*\)\s*\()|(?:\([\w\s]+\([\w\s]+\)[\w\s]+\))|(?:(?<!(?:mozilla\\/\d\.\d\s))\([^)[]+\[[^\]]+\][^)]*\))|(?:[^\s!][{([][^({[]+[{([][^}\])]+[}\])][\s+\",\d]*[}\])])|(?:\"\)?\]\W*\[)|(?:=\s*[^\s:;]+\s*[{([][^}\])]+[}\])];)",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def IE_octal(request):
        """
        function Detects the IE octal, hex and unicode entities
        xss csrf
        """
        return RiskLevels.NEGLIGIBLE if \
            re.search(r"(?:\\u00[a-f0-9]{2})|(?:\\x0*[a-f0-9]{2})|(?:\\\d{2,3})", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def directory_traversal(request):
        """
        function Detects basic directory traversal
        dt id lfi
        """
        return RiskLevels.MODERATE if \
            re.search(r"(?:(?:\\/|\\)?\.+(\\/|\\)(?:\.+)?)|(?:\w+\.exe\??\s)|(?:;\s*\w+\s*\\/[\w*-]+\\/)|(?:\d\.\dx\|)|(?:%(?:c0\.|af\.|5c\.))|(?:\\/(?:%2e){2})",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def directory_and(request):
        """
        function Detects specific directory and path traversal
        dt id lfi
        """
        return RiskLevels.MODERATE if \
            re.search(r"(?:%c0%ae\\/)|(?:(?:\\/|\\)(home|conf|usr|etc|proc|opt|s?bin|local|dev|tmp|kern|[br]oot|sys|system|windows|winnt|program|%[a-z_-]{3,}%)(?:\\/|\\))|(?:(?:\\/|\\)inetpub|localstart\.asp|boot\.ini)",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def inclusion_attempts(request):
        """
        function Detects etc\/passwd inclusion attempts
        dt id lfi
        """
        return RiskLevels.MODERATE if \
            re.search(r"(?:etc\\/\W*passwd)", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def encoded_unicode(request):
        """
        function Detects halfwidth\/fullwidth encoded unicode HTML breaking attempts
        xss csrf
        """
        return RiskLevels.SLIGHT if \
            re.search(r"(?:%u(?:ff|00|e\d)\w\w)|(?:(?:%(?:e\w|c[^3\W]|))(?:%\w\w)(?:%\w\w)?)", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def includes_VBSCript_JScript(request):
        """
        function Detects possible includes, VBSCript\/JScript encodeed and packed functions
        xss csrf id rfe
        """
        return RiskLevels.MODERATE if \
            re.search(r"(?:#@~\^\w+)|(?:\w+script:|@import[^\w]|;base64|base64,)|(?:\w\s*\([\w\s]+,[\w\s]+,[\w\s]+,[\w\s]+,[\w\s]+,[\w\s]+\))",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def DOM_miscellaneous_properties(request):
        """
        function Detects JavaScript DOM\/miscellaneous properties and methods
        xss csrf id rfe
        """
        return RiskLevels.MODERATE if \
            re.search(r"([^*:\s\w,.\\/?+-]\s*)?(?<![a-z]\s)(?<![a-z\\/_@\-\|])(\s*return\s*)?(?:create(?:element|attribute|textnode)|[a-z]+events?|setattribute|getelement\w+|appendchild|createrange|createcontextualfragment|removenode|parentnode|decodeuricomponent|\wettimeout|(?:ms)?setimmediate|option|useragent)(?(1)[^\w%\"]|(?:\s*[^@\s\w%\",.+\-]))",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def includes_and(request):
        """
        function Detects possible includes and typical script methods
        xss csrf id rfe
        """
        return RiskLevels.MODERATE if \
            re.search(r"([^*\s\w,.\\/?+-]\s*)?(?<![a-mo-z]\s)(?<![a-z\\/_@])(\s*return\s*)?(?:alert|inputbox|showmod(?:al|eless)dialog|showhelp|infinity|isnan|isnull|iterator|msgbox|executeglobal|expression|prompt|write(?:ln)?|confirm|dialog|urn|(?:un)?eval|exec|execscript|tostring|status|execute|window|unescape|navigate|jquery|getscript|extend|prototype)(?(1)[^\w%\"]|(?:\s*[^@\s\w%\",.:\\/+\-]))",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def object_properties(request):
        """
        function Detects JavaScript object properties and methods
        xss csrf id rfe
        """
        return RiskLevels.SLIGHT if \
            re.search(r"([^*:\s\w,.\\/?+-]\s*)?(?<![a-z]\s)(?<![a-z\\/_@])(\s*return\s*)?(?:hash|name|href|navigateandfind|source|pathname|close|constructor|port|protocol|assign|replace|back|forward|document|ownerdocument|window|top|this|self|parent|frames|_?content|date|cookie|innerhtml|innertext|csstext+?|outerhtml|print|moveby|resizeto|createstylesheet|stylesheets)(?(1)[^\w%\"]|(?:\s*[^@\\/\s\w%.+\-]))",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def array_properties(request):
        """
        function Detects JavaScript array properties and methods
        xss csrf id rfe
        """
        return RiskLevels.SLIGHT if \
            re.search(r"([^*:\s\w,.\\/?+-]\s*)?(?<![a-z]\s)(?<![a-z\\/_@\-\|])(\s*return\s*)?(?:join|pop|push|reverse|reduce|concat|map|shift|sp?lice|sort|unshift)(?(1)[^\w%\"]|(?:\s*[^@\s\w%,.+\-]))",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def string_properties(request):
        """
        function Detects JavaScript string properties and methods
        xss csrf id rfe
        """
        return RiskLevels.SLIGHT if \
            re.search(r"([^*:\s\w,.\\/?+-]\s*)?(?<![a-z]\s)(?<![a-z\\/_@\-\|])(\s*return\s*)?(?:set|atob|btoa|charat|charcodeat|charset|concat|crypto|frames|fromcharcode|indexof|lastindexof|match|navigator|toolbar|menubar|replace|regexp|slice|split|substr|substring|escape|\w+codeuri\w*)(?(1)[^\w%\"]|(?:\s*[^@\s\w%,.+\-]))",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def language_constructs(request):
        """
        function Detects JavaScript language constructs
        xss csrf id rfe
        """
        return RiskLevels.SLIGHT if \
            re.search(r"(?:\)\s*\[)|([^*\":\s\w,.\\/?+-]\s*)?(?<![a-z]\s)(?<![a-z_@\|])(\s*return\s*)?(?:globalstorage|sessionstorage|postmessage|callee|constructor|content|domain|prototype|try|catch|top|call|apply|url|function|object|array|string|math|if|for\s*(?:each)?|elseif|case|switch|regex|boolean|location|(?:ms)?setimmediate|settimeout|setinterval|void|setexpression|namespace|while)(?(1)[^\w%\"]|(?:\s*[^@\s\w%\".+\-\\/]))",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def basic_XSS(request):
        """
        function Detects very basic XSS probings
        xss csrf id rfe
        """
        return RiskLevels.SLIGHT if \
            re.search(r"(?:,\s*(?:alert|showmodaldialog|eval)\s*,)|(?::\s*eval\s*[^\s])|([^:\s\w,.\\/?+-]\s*)?(?<![a-z\\/_@])(\s*return\s*)?(?:(?:document\s*\.)?(?:.+\\/)?(?:alert|eval|msgbox|showmod(?:al|eless)dialog|showhelp|prompt|write(?:ln)?|confirm|dialog|open))\s*(?:[^.a-z\s\-]|(?:\s*[^\s\w,.@\\/+-]))|(?:java[\s\\/]*\.[\s\\/]*lang)|(?:\w\s*=\s*new\s+\w+)|(?:&\s*\w+\s*\)[^,])|(?:\+[\W\d]*new\s+\w+[\W\d]*\+)|(?:document\.\w)",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def XSS_probings(request):
        """
        function Detects advanced XSS probings via Script(), RexExp, constructors and XML namespaces
        xss csrf id rfe
        """
        return RiskLevels.MODERATE if \
            re.search(r"(?:=\s*(?:top|this|window|content|self|frames|_content))|(?:\\/\s*[gimx]*\s*[)}])|(?:[^\s]\s*=\s*script)|(?:\.\s*constructor)|(?:default\s+xml\s+namespace\s*=)|(?:\\/\s*\+[^+]+\s*\+\s*\\/)",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def location_document_property(request):
        """
        function Detects JavaScript location\/document property access and window access obfuscation
        xss csrf
        """
        return RiskLevels.MODERATE if \
            re.search(r"(?:\.\s*\w+\W*=)|(?:\W\s*(?:location|document)\s*\W[^({[;]+[({[;])|(?:\(\w+\?[:\w]+\))|(?:\w{2,}\s*=\s*\d+[^&\w]\w+)|(?:\]\s*\(\s*\w+)",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def obfuscated_JavaScript(request):
        """
        function Detects basic obfuscated JavaScript script injections
        xss csrf
        """
        return RiskLevels.MODERATE if \
            re.search(r"(?:[\".]script\s*\()|(?:\$\$?\s*\(\s*[\w\"])|(?:\\/[\w\s]+\\/\.)|(?:=\s*\\/\w+\\/\s*\.)|(?:(?:this|window|top|parent|frames|self|content)\[\s*[(,\"]*\s*[\w\$])|(?:,\s*new\s+\w+\s*[,;)])",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def JavaScript_script(request):
        """
        function Detects obfuscated JavaScript script injections
        xss csrf
        """
        return RiskLevels.MODERATE if \
            re.search(r"(?:=\s*[$\w]\s*[\(\[])|(?:\(\s*(?:this|top|window|self|parent|_?content)\s*\))|(?:src\s*=s*(?:\w+:|\\/\\/))|(?:\w+\[(\"\w+\"|\w+\|\|))|(?:[\d\W]\|\|[\d\W]|\W=\w+,)|(?:\\/\s*\+\s*[a-z\"])|(?:=\s*\$[^([]*\()|(?:=\s*\(\s*\")",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def cookie_stealing(request):
        """
        function Detects JavaScript cookie stealing and redirection attempts
        xss csrf
        """
        return RiskLevels.SLIGHT if \
            re.search(r"(?:[^:\s\w]+\s*[^\w\\/](href|protocol|host|hostname|pathname|hash|port|cookie)[^\w])", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def URL_injections(request):
        """
        function Detects data: URL injections, VBS injections and common URI schemes
        xss rfe
        """
        return RiskLevels.MODERATE if \
            re.search(r"(?:(?:vbs|vbscript|data):.*[,+])|(?:\w+\s*=\W*(?!https?)\w+:)|(jar:\w+:)|(=\s*\"?\s*vbs(?:ript)?:)|(language\s*=\s?\"?\s*vbs(?:ript)?)|on\w+\s*=\*\w+\-\"?",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def firefoxurl_injections(request):
        """
        function Detects IE firefoxurl injections, cache poisoning attempts and local file inclusion\/execution
        xss rfe lfi csrf
        """
        return RiskLevels.MODERATE if \
            re.search(r"(?:firefoxurl:\w+\|)|(?:(?:file|res|telnet|nntp|news|mailto|chrome)\s*:\s*[%&#xu\\/]+)|(wyciwyg|firefoxurl\s*:\s*\\/\s*\\/)",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def and_behavior(request):
        """
        function Detects bindings and behavior injections
        xss csrf rfe
        """
        return RiskLevels.SLIGHT if \
            re.search(r"(?:binding\s?=|moz-binding|behavior\s?=)|(?:[\s\\/]style\s*=\s*[-\\])", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def XSS_concatenation(request):
        """
        function Detects common XSS concatenation patterns 1\/2
        xss csrf id rfe
        """
        return RiskLevels.SLIGHT if \
            re.search(r"(?:=\s*\w+\s*\+\s*\")|(?:\+=\s*\(\s\")|(?:!+\s*[\d.,]+\w?\d*\s*\?)|(?:=\s*\[s*\])|(?:\"\s*\+\s*\")|(?:[^\s]\[\s*\d+\s*\]\s*[;+])|(?:\"\s*[&|]+\s*\")|(?:\\/\s*\?\s*\")|(?:\\/\s*\)\s*\[)|(?:\d\?.+:\d)|(?:]\s*\[\W*\w)|(?:[^\s]\s*=\s*\\/)",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def XSS_concatenation(request):
        """
        function Detects common XSS concatenation patterns 2\/2
        xss csrf id rfe
        """
        return RiskLevels.SLIGHT if \
            re.search(r"(?:=\s*\d*\.\d*\?\d*\.\d*)|(?:[|&]{2,}\s*\")|(?:!\d+\.\d*\?\")|(?:\\/:[\w.]+,)|(?:=[\d\W\s]*\[[^]]+\])|(?:\?\w+:\w+)",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def event_handlers(request):
        """
        function Detects possible event handlers
        xss csrf
        """
        return RiskLevels.SLIGHT if \
            re.search(r"(?:[^\w\s=]on(?!g\&gt;)\w+[^=_+-]*=[^$]+(?:\W|\&gt;)?)", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def script_tags(request):
        """
        function Detects obfuscated script tags and XML wrapped HTML
        x s s
        """
        return RiskLevels.SLIGHT if \
            re.search(r"(?:\<\w*:?\s(?:[^\>]*)t(?!rong))|(?:\<scri)|(<\w+:\w+)", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def in_closing(request):
        """
        function Detects attributes in closing tags and conditional compilation tokens
        xss csrf
        """
        return RiskLevels.SLIGHT if \
            re.search(r"(?:\<\\/\w+\s\w+)|(?:@(?:cc_on|set)[\s@,\"=])", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def comment_types(request):
        """
        function Detects common comment types
        xss csrf id
        """
        return RiskLevels.SLIGHT if \
            re.search(r"(?:--[^\n]*$)|(?:\<!-|-->)|(?:[^*]\\/\*|\*\\/[^*])|(?:(?:[\W\d]#|--|{)$)|(?:\\/{3,}.*$)|(?:<!\[\W)|(?:\]!>)",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def href_injections(request):
        """
        function Detects base href injections and XML entity injections
        xss csrf id
        """
        return RiskLevels.MODERATE if \
            re.search(r"(?:\<base\s+)|(?:<!(?:element|entity|\[CDATA))", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def malicious_html(request):
        """
        function Detects possibly malicious html elements including some attributes
        xss csrf id rfe lfi
        """
        return RiskLevels.SLIGHT if \
            re.search(r"(?:\<[\\/]?(?:[i]?frame|applet|isindex|marquee|keygen|script|audio|video|input|button|textarea|style|base|body|meta|link|object|embed|param|plaintext|xm\w+|image|im(?:g|port)))",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def and_other(request):
        """
        function Detects nullbytes and other dangerous characters
        id rfe xss
        """
        return RiskLevels.MODERATE if \
            re.search(r"(?:\\x[01fe][\db-ce-f])|(?:%[01fe][\db-ce-f])|(?:&#[01fe][\db-ce-f])|(?:\\[01fe][\db-ce-f])|(?:&#x[01fe][\db-ce-f])",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def comments_conditions(request):
        """
        function Detects MySQL comments, conditions and ch(a)r injections
        sqli id lfi
        """
        return RiskLevels.MODERATE if \
            re.search(r"(?:\)\s*when\s*\d+\s*then)|(?:\"\s*(?:#|--|{))|(?:\\/\*!\s?\d+)|(?:ch(?:a)?r\s*\(\s*\d)|(?:(?:(n?and|x?or|not)\s+|\|\||\&\&)\s*\w+\()",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def SQL_injection(request):
        """
        function Detects conditional SQL injection attempts
        sqli id lfi
        """
        return RiskLevels.MODERATE if \
            re.search(r"(?:[\s()]case\s*\()|(?:\)\s*like\s*\()|(?:having\s*[^\s]+\s*[^\w\s])|(?:if\s?\([\d\w]\s*[=<>~])",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def SQL_injection(request):
        """
        function Detects classic SQL injection probings 1\/2
        sqli id lfi
        """
        return RiskLevels.MODERATE if \
            re.search(r"(?:\"\s*or\s*\"?\d)|(?:\\x(?:23|27|3d))|(?:^.?\"$)|(?:(?:^[\"\\]*(?:[\d\"]+|[^\"]+\"))+\s*(?:n?and|x?or|not|\|\||\&\&)\s*[\w\"[+&!@(),.-])|(?:[^\w\s]\w+\s*[|-]\s*\"\s*\w)|(?:@\w+\s+(and|or)\s*[\"\d]+)|(?:@[\w-]+\s(and|or)\s*[^\w\s])|(?:[^\w\s:]\s*\d\W+[^\w\s]\s*\".)|(?:\Winformation_schema|table_name\W)",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def SQL_injection(request):
        """
        function Detects classic SQL injection probings 2\/2
        sqli id lfi
        """
        return RiskLevels.MODERATE if \
            re.search(r"(?:\"\s*\*.+(?:or|id)\W*\"\d)|(?:\^\")|(?:^[\w\s\"-]+(?<=and\s)(?<=or\s)(?<=xor\s)(?<=nand\s)(?<=not\s)(?<=\|\|)(?<=\&\&)\w+\()|(?:\"[\s\d]*[^\w\s]+\W*\d\W*.*[\"\d])|(?:\"\s*[^\w\s?]+\s*[^\w\s]+\s*\")|(?:\"\s*[^\w\s]+\s*[\W\d].*(?:#|--))|(?:\".*\*\s*\d)|(?:\"\s*or\s[^\d]+[\w-]+.*\d)|(?:[()*<>%+-][\w-]+[^\w\s]+\"[^,])",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def SQL_authentication(request):
        """
        function Detects basic SQL authentication bypass attempts 1\/3
        sqli id lfi
        """
        return RiskLevels.CRITICAL if \
            re.search(r"(?:\d\"\s+\"\s+\d)|(?:^admin\s*\"|(\\/\*)+\"+\s?(?:--|#|\\/\*|{)?)|(?:\"\s*or[\w\s-]+\s*[+<>=(),-]\s*[\d\"])|(?:\"\s*[^\w\s]?=\s*\")|(?:\"\W*[+=]+\W*\")|(?:\"\s*[!=|][\d\s!=+-]+.*[\"(].*$)|(?:\"\s*[!=|][\d\s!=]+.*\d+$)|(?:\"\s*like\W+[\w\"(])|(?:\sis\s*0\W)|(?:where\s[\s\w\.,-]+\s=)|(?:\"[<>~]+\")",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def SQL_authentication(request):
        """
        function Detects basic SQL authentication bypass attempts 2\/3
        sqli id lfi
        """
        return RiskLevels.CRITICAL if \
            re.search(r"(?:union\s*(?:all|distinct|[(!@]*)\s*[([]*\s*select)|(?:\w+\s+like\s+\")|(?:like\s * \"\%)|(?:\"\s*like\W*[\"\d])|(?:\"\s*(?:n?and|x?or|not |\|\||\&\&)\s+[\s\w]+=\s*\w+\s*having)|(?:\"\s*\*\s*\w+\W+\")|(?:\"\s*[^?\w\s=.,;)(]+\s*[(@\"]*\s*\w+\W+\w)|(?:select\s*[\[\]()\s\w\.,\"-]+from)|(?:find_in_set\s*\()", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def SQL_authentication(request):
        """
        function Detects basic SQL authentication bypass attempts 3\/3
        sqli id lfi
        """
        return RiskLevels.CRITICAL if \
            re.search(r"(?:in\s*\(+\s*select)|(?:(?:n?and|x?or|not |\|\||\&\&)\s+[\s\w+]+(?:regexp\s*\(|sounds\s+like\s*\"|[=\d]+x))|(\"\s*\d\s*(?:--|#))|(?:\"[%&<>^=]+\d\s*(=|or))|(?:\"\W+[\w+-]+\s*=\s*\d\W+\")|(?:\"\s*is\s*\d.+\"?\w)|(?:\"\|?[\w-]{3,}[^\w\s.,]+\")|(?:\"\s*is\s*[\d.]+\s*\W.*\")",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def basic_SQL(request):
        """
        function Detects concatenated basic SQL injection and SQLLFI attempts
        sqli id lfi
        """
        return RiskLevels.MODERATE if \
            re.search(r"(?:[\d\W]\s+as\s*[\"\w]+\s*from)|(?:^[\W\d]+\s*(?:union|select|create|rename|truncate|load|alter|delete|update|insert|desc))|(?:(?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s+(?:(?:group_)concat|char|load_file)\s?\(?)|(?:end\s*\);)|(\"\s+regexp\W)|(?:[\s(]load_file\s*\()",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def SQL_injection(request):
        """
        function Detects chained SQL injection attempts 1\/2
        sqli id
        """
        return RiskLevels.MODERATE if \
            re.search(r"(?:@.+=\s*\(\s*select)|(?:\d+\s*or\s*\d+\s*[\-+])|(?:\\/\w+;?\s+(?:having|and|or|select)\W)|(?:\d\s+group\s+by.+\()|(?:(?:;|#|--)\s*(?:drop|alter))|(?:(?:;|#|--)\s*(?:update|insert)\s*\w{2,})|(?:[^\w]SET\s*@\w+)|(?:(?:n?and|x?or|not |\|\||\&\&)[\s(]+\w+[\s)]*[!=+]+[\s\d]*[\"=()])",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def SQL_injection(request):
        """
        function Detects chained SQL injection attempts 2\/2
        sqli id
        """
        return RiskLevels.MODERATE if \
            re.search(r"(?:\"\s+and\s*=\W)|(?:\(\s*select\s*\w+\s*\()|(?:\*\\/from)|(?:\+\s*\d+\s*\+\s*@)|(?:\w\"\s*(?:[-+=|@]+\s*)+[\d(])|(?:coalesce\s*\(|@@\w+\s*[^\w\s])|(?:\W!+\"\w)|(?:\";\s*(?:if|while|begin))|(?:\"[\s\d]+=\s*\d)|(?:order\s+by\s+if\w*\s*\()|(?:[\s(]+case\d*\W.+[tw]hen[\s(])",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def benchmark_and(request):
        """
        function Detects SQL benchmark and sleep injection attempts including conditional queries
        sqli id
        """
        return RiskLevels.SLIGHT if \
            re.search(r"(?:(select|;)\s+(?:benchmark|if|sleep)\s*?\(\s*\(?\s*\w+)", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def UDF_injection(request):
        """
        function Detects MySQL UDF injection and other data\/structure manipulation attempts
        sqli id
        """
        return RiskLevels.MODERATE if \
            re.search(r"(?:create\s+function\s+\w+\s+returns)|(?:;\s*(?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s*[\[(]?\w{2,})",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def charset_switch(request):
        """
        function Detects MySQL charset switch and MSSQL DoS attempts
        sqli id
        """
        return RiskLevels.MODERATE if \
            re.search(r"(?:alter\s*\w+.*character\s+set\s+\w+)|(\";\s*waitfor\s+time\s+\")|(?:\";.*:\s*goto)", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def and_PostgreSQL(request):
        """
        function Detects MySQL and PostgreSQL stored procedure\/function injections
        sqli id
        """
        return RiskLevels.CRITICAL if \
            re.search(r"(?:procedure\s+analyse\s*\()|(?:;\s*(declare|open)\s+[\w-]+)|(?:create\s+(procedure|function)\s*\w+\s*\(\s*\)\s*-)|(?:declare[^\w]+[@#]\s*\w+)|(exec\s*\(\s*@)",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def pg_sleep_injection(request):
        """
        function Detects Postgres pg_sleep injection, waitfor delay attacks and database shutdown attempts
        sqli id
        """
        return RiskLevels.MODERATE if \
            re.search(r"(?:select\s*pg_sleep)|(?:waitfor\s*delay\s?\"+\s?\d)|(?:;\s*shutdown\s*(?:;|--|#|\\/\*|{))", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def code_execution(request):
        """
        function Detects MSSQL code execution and information gathering attempts
        sqli id
        """
        return RiskLevels.MODERATE if \
            re.search(r"(?:\sexec\s+xp_cmdshell)|(?:\"\s*!\s*[\"\w])|(?:from\W+information_schema\W)|(?:(?:(?:current_)?user|database|schema|connection_id)\s*\([^\)]*)|(?:\";?\s*(?:select|union|having)\s*[^\s])|(?:\wiif\s*\()|(?:exec\s+master\.)|(?:union select @)|(?:union[\w(\s]*select)|(?:select.*\w?user\()|(?:into[\s+]+(?:dump|out)file\s*\")",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def AGAINST_MERGE(request):
        """
        function Detects MATCH AGAINST, MERGE, EXECUTE IMMEDIATE and HAVING injections
        sqli id
        """
        return RiskLevels.MODERATE if \
            re.search(r"(?:merge.*using\s*\()|(execute\s*immediate\s*\")|(?:\W+\d*\s*having\s*[^\s\-])|(?:match\s*[\w(),+-]+\s*against\s*\()",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def comment_space_obfuscated_injections(request):
        """
        function Detects MySQL comment-\/space-obfuscated injections and backtick termination
        sqli id
        """
        return RiskLevels.MODERATE if \
            re.search(r"(?:,.*[)\da-f\"]\"(?:\".*\"|\Z|[^\"]+))|(?:\Wselect.+\W*from)|((?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s*\(\s*space\s*\()",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def injection_attempts(request):
        """
        function Detects code injection attempts 1\/3
        id rfe lfi
        """
        return RiskLevels.CRITICAL if \
            re.search(r"(?:@[\w-]+\s*\()|(?:]\s*\(\s*[\"!]\s*\w)|(?:<[?%](?:php)?.*(?:[?%]>)?)|(?:;[\s\w|]*\$\w+\s*=)|(?:\$\w+\s*=(?:(?:\s*\$?\w+\s*[(;])|\s*\".*\"))|(?:;\s*\{\W*\w+\s*\()",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def injection_attempts(request):
        """
        function Detects code injection attempts 2\/3
        id rfe lfi
        """
        return RiskLevels.CRITICAL if \
            re.search(r"(?:(?:[;]+|(<[?%](?:php)?)).*(?:define|eval|file_get_contents|include|require|require_once|set|shell_exec|phpinfo|system|passthru|preg_\w+|execute)\s*[\"(@])",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def injection_attempts(request):
        """
        function Detects code injection attempts 3\/3
        id rfe lfi
        """
        return RiskLevels.CRITICAL if \
            re.search(r"(?:(?:[;]+|(<[?%](?:php)?)).*[^\w](?:echo|print|print_r|var_dump|[fp]open))|(?:;\s*rm\s+-\w+\s+)|(?:;.*{.*\$\w+\s*=)|(?:\$\w+\s*\[\]\s*=\s*)",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def function_declarations(request):
        """
        function Detects common function declarations and special JS operators
        id rfe lfi
        """
        return RiskLevels.MODERATE if \
            re.search(r"(?:function[^(]*\([^)]*\))|(?:(?:delete|void|throw|instanceof|new|typeof)[^\w.]+\w+\s*[([])|([)\]]\s*\.\s*\w+\s*=)|(?:\(\s*new\s+\w+\s*\)\.)",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def mail_header(request):
        """
        function Detects common mail header injections
        id spam
        """
        return RiskLevels.MODERATE if \
            re.search(r"(?:[\w.-]+@[\w.-]+%(?:[01][\db-ce-f])+\w+:)", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def echo_shellcode(request):
        """
        function Detects perl echo shellcode injection and LDAP vectors
        lfi rfe
        """
        return RiskLevels.MODERATE if \
            re.search(r"(?:\.pl\?\w+=\w?\|\w+;)|(?:\|\(\w+=\*)|(?:\*\s*\)+\s*;)", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def XSS_DoS(request):
        """
        function Detects basic XSS DoS attempts
        rfe dos
        """
        return RiskLevels.MODERATE if \
            re.search(r"(?:(^|\W)const\s+[\w\-]+\s*=)|(?:(?:do|for|while)\s*\([^;]+;+\))|(?:(?:^|\W)on\w+\s*=[\w\W]*(?:on\w+|alert|eval|print|confirm|prompt))|(?:groups=\d+\(\w+\))|(?:(.)\1{128,})",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def attack_vectors(request):
        """
        function Detects unknown attack vectors based on PHPIDS Centrifuge detection
        xss csrf id rfe lfi
        """
        return RiskLevels.CRITICAL if \
            re.search(r"(?:\({2,}\+{2,}:{2,})|(?:\({2,}\+{2,}:+)|(?:\({3,}\++:{2,})|(?:\$\[!!!\])", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def breaking_injections(request):
        """
        function Finds attribute breaking injections including obfuscated attributes
        xss csrf
        """
        return RiskLevels.SLIGHT if \
            re.search(r"(?:[\s\\/\"]+[-\w\\/\\\*]+\s*=.+(?:\\/\s*>))", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def VBScript_injection(request):
        """
        function Finds basic VBScript injection attempts
        xss csrf
        """
        return RiskLevels.SLIGHT if \
            re.search(r"(?:(?:msgbox|eval)\s*\+|(?:language\s*=\*vbscript))", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def MongoDB_SQL(request):
        """
        function Finds basic MongoDB SQL injection attempts
        s q l i
        """
        return RiskLevels.SLIGHT if \
            re.search(r"(?:\[\$(?:ne|eq|lte?|gte?|n?in|mod|all|size|exists|type|slice|or)\])", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def attribute_injection(request):
        """
        function Finds malicious attribute injection attempts and MHTML attacks
        xss csrf
        """
        return RiskLevels.MODERATE if \
            re.search(r"(?:[\s\d\\/\"]+(?:on\w+|style|poster|background)=[$\"\w])|(?:-type\s*:\s*multipart)", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def sqli_tests(request):
        """
        function Detects blind sqli tests using sleep() or benchmark().
        sqli id
        """
        return RiskLevels.SLIGHT if \
            re.search(r"(?:(sleep\((\s*)(\d*)(\s*)\)|benchmark\((.*)\,(.*)\)))", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def is_trying(request):
        """
        function An attacker is trying to locate a file to read or write.
        files id
        """
        return RiskLevels.SLIGHT if \
            re.search(r"(?:(\%SYSTEMROOT\%))", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def a_format(request):
        """
        function Looking for a format string attack
        f o r m a t   s t r i n g
        """
        return RiskLevels.SLIGHT if \
            re.search(r"(?:(((.*)\%[c|d|i|e|f|g|o|s|u|x|p|n]){8}))", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def basic_sql(request):
        """
        function Looking for basic sql injection. Common attack string for mysql, oracle and others.
        sqli id
        """
        return RiskLevels.SLIGHT if \
            re.search(r"(?:(union(.*)select(.*)from))", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def integer_overflow(request):
        """
        function Looking for integer overflow attacks, these are taken from skipfish, except 2.2250738585072007e-308 is the "magic number" crash
        sqli id
        """
        return RiskLevels.SLIGHT if \
            re.search(r"(?:^(-0000023456|4294967295|4294967296|2147483648|2147483647|0000012345|-2147483648|-2147483649|0000023456|2.2250738585072007e-308|1e309)$)",request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def comment_filter(request):
        """
        function Detects SQL comment filter evasion
        format string
        """
        return RiskLevels.SLIGHT if \
            re.search(r"(?:%23.*?%0a)", request) \
            else RiskLevels.NO_RISK
