import re
from detective.toolbox import RiskLevels


class BasicChecks:
    @staticmethod
    def breaking_injections(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""(?:[\s\\/\"]+[-\w\\/\\\*]+\s*=.+(?:\\/\s*>))""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def html_breaking_injections(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""(?:\"[^\"]*[^-]?>)|(?:[^\w\s]\s*\\/>)|(?:>\")""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def attribute_breaking_injections(request) -> RiskLevels:
        return RiskLevels.SLIGHT \
            if re.search(r"""(?:\"+.*[<=]\s*\"[^\"]+\")|(?:\"\s*\w+\s*=)|(?:>\w=\\/)|(?:#.+\)[\"\s]*>)|(?:\"\s*(?:src|style|on\w+)\s*=\s*\")|(?:[^\"]?\"[,;\s]+\w*[\[\(])""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def attribute_breaking(request) -> RiskLevels:
        return RiskLevels.NEGLIGIBLE if re.search(r"""(?:^>[\w\s]*<\\/?\w{2,}>)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def name_json(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""(?:[+\\/]\s*name[\W\d]*[)+])|(?:;\W*url\s*=)|(?:[^\w\s\\/?:>]\s*(?:location|referrer|name)\s*[^\\/\w\s-])""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def xss_payload(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""(?:\W\s*hash\s*[^\w\s-])|(?:\w+=\W*[^,]*,[^\s(]\s*\()|(?:\?\"[^\s\"]\":)|(?:(?<!\\/)__[a-z]+__)|(?:(?:^|[\s)\]\}])(?:s|g)etter\s*=)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def contained_xss(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""(?:with\s*\(\s*.+\s*\)\s*\w+\s*\()|(?:(?:do|while|for)\s*\([^)]*\)\s*\{)|(?:\\/[\w\s]*\[\W*\w)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def with_ternary(request) -> RiskLevels:
        return RiskLevels.MODERATE if re.search(r"""(?:[=(].+\?.+:)|(?:with\([^)]*\)\))|(?:\.\s*source\W)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def javascript_functions(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""(?:\\/\w*\s*\)\s*\()|(?:\([\w\s]+\([\w\s]+\)[\w\s]+\))|(?:(?<!(?:mozilla\\/\d\.\d\s))\([^)[]+\[[^\]]+\][^)]*\))|(?:[^\s!][{([][^({[]+[{([][^}\])]+[}\])][\s+\",\d]*[}\])])|(?:\"\)?\]\W*\[)|(?:=\s*[^\s:;]+\s*[{([][^}\])]+[}\])];)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def ie_octal(request) -> RiskLevels:
        return RiskLevels.NEGLIGIBLE if re.search(r"""(?:\\u00[a-f0-9]{2})|(?:\\x0*[a-f0-9]{2})|(?:\\\d{2,3})""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def directory_traversal(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""(?:(?:\\/|\\)?\.+(\\/|\\)(?:\.+)?)|(?:\w+\.exe\??\s)|(?:;\s*\w+\s*\\/[\w*-]+\\/)|(?:\d\.\dx\|)|(?:%(?:c0\.|af\.|5c\.))|(?:\\/(?:%2e){2})""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def directory_and(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""(?:%c0%ae\\/)|(?:(?:\\/|\\)(home|conf|usr|etc|proc|opt|s?bin|local|dev|tmp|kern|[br]oot|sys|system|windows|winnt|program|%[a-z_-]{3,}%)(?:\\/|\\))|(?:(?:\\/|\\)inetpub|localstart\.asp|boot\.ini)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def inclusion_attempts(request) -> RiskLevels:
        return RiskLevels.MODERATE if re.search(r"""(?:etc\\/\W*passwd)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def encoded_unicode(request) -> RiskLevels:
        return RiskLevels.SLIGHT \
            if re.search(r"""(?:%u(?:ff|00|e\d)\w\w)|(?:(?:%(?:e\w|c[^3\W]|))(?:%\w\w)(?:%\w\w)?)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def includes_vbscript_jscript(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""(?:#@~\^\w+)|(?:\w+script:|@import[^\w]|;base64|base64,)|(?:\w\s*\([\w\s]+,[\w\s]+,[\w\s]+,[\w\s]+,[\w\s]+,[\w\s]+\))""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def dom_miscellaneous_properties(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""([^*:\s\w,.\\/?+-]\s*)?(?<![a-z]\s)(?<![a-z\\/_@\-\|])(\s*return\s*)?(?:create(?:element|attribute|textnode)|[a-z]+events?|setattribute|getelement\w+|appendchild|createrange|createcontextualfragment|removenode|parentnode|decodeuricomponent|\wettimeout|(?:ms)?setimmediate|option|useragent)(?(1)[^\w%\"]|(?:\s*[^@\s\w%\",.+\-]))""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def includes_and(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""([^*\s\w,.\\/?+-]\s*)?(?<![a-mo-z]\s)(?<![a-z\\/_@])(\s*return\s*)?(?:alert|inputbox|showmod(?:al|eless)dialog|showhelp|infinity|isnan|isnull|iterator|msgbox|executeglobal|expression|prompt|write(?:ln)?|confirm|dialog|urn|(?:un)?eval|exec|execscript|tostring|status|execute|window|unescape|navigate|jquery|getscript|extend|prototype)(?(1)[^\w%\"]|(?:\s*[^@\s\w%\",.:\\/+\-]))""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def object_properties(request) -> RiskLevels:
        return RiskLevels.SLIGHT \
            if re.search(r"""([^*:\s\w,.\\/?+-]\s*)?(?<![a-z]\s)(?<![a-z\\/_@])(\s*return\s*)?(?:hash|name|href|navigateandfind|source|pathname|close|constructor|port|protocol|assign|replace|back|forward|document|ownerdocument|window|top|this|self|parent|frames|_?content|date|cookie|innerhtml|innertext|csstext+?|outerhtml|print|moveby|resizeto|createstylesheet|stylesheets)(?(1)[^\w%\"]|(?:\s*[^@\\/\s\w%.+\-]))""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def array_properties(request) -> RiskLevels:
        return RiskLevels.SLIGHT \
            if re.search(r"""([^*:\s\w,.\\/?+-]\s*)?(?<![a-z]\s)(?<![a-z\\/_@\-\|])(\s*return\s*)?(?:join|pop|push|reverse|reduce|concat|map|shift|sp?lice|sort|unshift)(?(1)[^\w%\"]|(?:\s*[^@\s\w%,.+\-]))""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def string_properties(request) -> RiskLevels:
        return RiskLevels.SLIGHT \
            if re.search(r"""([^*:\s\w,.\\/?+-]\s*)?(?<![a-z]\s)(?<![a-z\\/_@\-\|])(\s*return\s*)?(?:set|atob|btoa|charat|charcodeat|charset|concat|crypto|frames|fromcharcode|indexof|lastindexof|match|navigator|toolbar|menubar|replace|regexp|slice|split|substr|substring|escape|\w+codeuri\w*)(?(1)[^\w%\"]|(?:\s*[^@\s\w%,.+\-]))""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def language_constructs(request) -> RiskLevels:
        return RiskLevels.SLIGHT \
            if re.search(r"""(?:\)\s*\[)|([^*\":\s\w,.\\/?+-]\s*)?(?<![a-z]\s)(?<![a-z_@\|])(\s*return\s*)?(?:globalstorage|sessionstorage|postmessage|callee|constructor|content|domain|prototype|try|catch|top|call|apply|url|function|object|array|string|math|if|for\s*(?:each)?|elseif|case|switch|regex|boolean|location|(?:ms)?setimmediate|settimeout|setinterval|void|setexpression|namespace|while)(?(1)[^\w%\"]|(?:\s*[^@\s\w%\".+\-\\/]))""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def basic_xss(request) -> RiskLevels:
        return RiskLevels.SLIGHT \
            if re.search(r"""(?:,\s*(?:alert|showmodaldialog|eval)\s*,)|(?::\s*eval\s*[^\s])|([^:\s\w,.\\/?+-]\s*)?(?<![a-z\\/_@])(\s*return\s*)?(?:(?:document\s*\.)?(?:.+\\/)?(?:alert|eval|msgbox|showmod(?:al|eless)dialog|showhelp|prompt|write(?:ln)?|confirm|dialog|open))\s*(?:[^.a-z\s\-]|(?:\s*[^\s\w,.@\\/+-]))|(?:java[\s\\/]*\.[\s\\/]*lang)|(?:\w\s*=\s*new\s+\w+)|(?:&\s*\w+\s*\)[^,])|(?:\+[\W\d]*new\s+\w+[\W\d]*\+)|(?:document\.\w)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def xss_probings(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""(?:=\s*(?:top|this|window|content|self|frames|_content))|(?:\\/\s*[gimx]*\s*[)}])|(?:[^\s]\s*=\s*script)|(?:\.\s*constructor)|(?:default\s+xml\s+namespace\s*=)|(?:\\/\s*\+[^+]+\s*\+\s*\\/)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def location_document_property(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""(?:\.\s*\w+\W*=)|(?:\W\s*(?:location|document)\s*\W[^({[;]+[({[;])|(?:\(\w+\?[:\w]+\))|(?:\w{2,}\s*=\s*\d+[^&\w]\w+)|(?:\]\s*\(\s*\w+)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def obfuscated_javascript(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""(?:[\".]script\s*\()|(?:\$\$?\s*\(\s*[\w\"])|(?:\\/[\w\s]+\\/\.)|(?:=\s*\\/\w+\\/\s*\.)|(?:(?:this|window|top|parent|frames|self|content)\[\s*[(,\"]*\s*[\w\$])|(?:,\s*new\s+\w+\s*[,;)])""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def javascript_script(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""(?:=\s*[$\w]\s*[\(\[])|(?:\(\s*(?:this|top|window|self|parent|_?content)\s*\))|(?:src\s*=s*(?:\w+:|\\/\\/))|(?:\w+\[(\"\w+\"|\w+\|\|))|(?:[\d\W]\|\|[\d\W]|\W=\w+,)|(?:\\/\s*\+\s*[a-z\"])|(?:=\s*\$[^([]*\()|(?:=\s*\(\s*\")""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def cookie_stealing(request) -> RiskLevels:
        return RiskLevels.SLIGHT \
            if re.search(r"""(?:[^:\s\w]+\s*[^\w\\/](href|protocol|host|hostname|pathname|hash|port|cookie)[^\w])""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def url_injections(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""(?:(?:vbs|vbscript|data):.*[,+])|(?:\w+\s*=\W*(?!https?)\w+:)|(jar:\w+:)|(=\s*\"?\s*vbs(?:ript)?:)|(language\s*=\s?\"?\s*vbs(?:ript)?)|on\w+\s*=\*\w+\-\"?""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def firefox_url_injections(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""(?:firefoxurl:\w+\|)|(?:(?:file|res|telnet|nntp|news|mailto|chrome)\s*:\s*[%&#xu\\/]+)|(wyciwyg|firefoxurl\s*:\s*\\/\s*\\/)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def and_behavior(request) -> RiskLevels:
        return RiskLevels.SLIGHT \
            if re.search(r"""(?:binding\s?=|moz-binding|behavior\s?=)|(?:[\s\\/]style\s*=\s*[-\\])""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def xss_concatenation_1(request) -> RiskLevels:
        return RiskLevels.SLIGHT \
            if re.search(r"""(?:=\s*\w+\s*\+\s*\")|(?:\+=\s*\(\s\")|(?:!+\s*[\d.,]+\w?\d*\s*\?)|(?:=\s*\[s*\])|(?:\"\s*\+\s*\")|(?:[^\s]\[\s*\d+\s*\]\s*[;+])|(?:\"\s*[&|]+\s*\")|(?:\\/\s*\?\s*\")|(?:\\/\s*\)\s*\[)|(?:\d\?.+:\d)|(?:]\s*\[\W*\w)|(?:[^\s]\s*=\s*\\/)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def xss_concatenation_2(request) -> RiskLevels:
        return RiskLevels.SLIGHT \
            if re.search(r"""(?:=\s*\d*\.\d*\?\d*\.\d*)|(?:[|&]{2,}\s*\")|(?:!\d+\.\d*\?\")|(?:\\/:[\w.]+,)|(?:=[\d\W\s]*\[[^]]+\])|(?:\?\w+:\w+)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def event_handlers(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""(?:[^\w\s=]on(?!g\&gt;)\w+[^=_+-]*=[^$]+(?:\W|\&gt;)?)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def script_tags(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""(?:\<\w*:?\s(?:[^\>]*)t(?!rong))|(?:\<scri)|(<\w+:\w+)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def in_closing(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""(?:\<\\/\w+\s\w+)|(?:@(?:cc_on|set)[\s@,\"=])""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def comment_types(request) -> RiskLevels:
        return RiskLevels.SLIGHT \
            if re.search(r"""(?:--[^\n]*$)|(?:\<!-|-->)|(?:[^*]\\/\*|\*\\/[^*])|(?:(?:[\W\d]#|--|{)$)|(?:\\/{3,}.*$)|(?:<!\[\W)|(?:\]!>)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def href_injections(request) -> RiskLevels:
        return RiskLevels.MODERATE if re.search(r"""(?:\<base\s+)|(?:<!(?:element|entity|\[CDATA))""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def malicious_html(request) -> RiskLevels:
        return RiskLevels.SLIGHT \
            if re.search(r"""(?:\<[\\/]?(?:[i]?frame|applet|isindex|marquee|keygen|script|audio|video|input|button|textarea|style|base|body|meta|link|object|embed|param|plaintext|xm\w+|image|im(?:g|port)))""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def and_other(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""(?:\\x[01fe][\db-ce-f])|(?:%[01fe][\db-ce-f])|(?:&#[01fe][\db-ce-f])|(?:\\[01fe][\db-ce-f])|(?:&#x[01fe][\db-ce-f])""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def comments_conditions(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""(?:\)\s*when\s*\d+\s*then)|(?:\"\s*(?:#|--|{))|(?:\\/\*!\s?\d+)|(?:ch(?:a)?r\s*\(\s*\d)|(?:(?:(n?and|x?or|not)\s+|\|\||\&\&)\s*\w+\()""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def conditional_sql_injection(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""(?:[\s()]case\s*\()|(?:\)\s*like\s*\()|(?:having\s*[^\s]+\s*[^\w\s])|(?:if\s?\([\d\w]\s*[=<>~])""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def classic_sql_injection_1(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""(?:\"\s*or\s*\"?\d)|(?:\\x(?:23|27|3d))|(?:^.?\"$)|(?:(?:^[\"\\]*(?:[\d\"]+|[^\"]+\"))+\s*(?:n?and|x?or|not|\|\||\&\&)\s*[\w\"[+&!@(),.-])|(?:[^\w\s]\w+\s*[|-]\s*\"\s*\w)|(?:@\w+\s+(and|or)\s*[\"\d]+)|(?:@[\w-]+\s(and|or)\s*[^\w\s])|(?:[^\w\s:]\s*\d\W+[^\w\s]\s*\".)|(?:\Winformation_schema|table_name\W)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def classic_sql_injection_2(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""(?:\"\s*\*.+(?:or|id)\W*\"\d)|(?:\^\")|(?:^[\w\s\"-]+(?<=and\s)(?<=or\s)(?<=xor\s)(?<=nand\s)(?<=not\s)(?<=\|\|)(?<=\&\&)\w+\()|(?:\"[\s\d]*[^\w\s]+\W*\d\W*.*[\"\d])|(?:\"\s*[^\w\s?]+\s*[^\w\s]+\s*\")|(?:\"\s*[^\w\s]+\s*[\W\d].*(?:#|--))|(?:\".*\*\s*\d)|(?:\"\s*or\s[^\d]+[\w-]+.*\d)|(?:[()*<>%+-][\w-]+[^\w\s]+\"[^,])""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def sql_authentication_1(request) -> RiskLevels:
        return RiskLevels.CRITICAL \
            if re.search(r"""(?:\d\"\s+\"\s+\d)|(?:^admin\s*\"|(\\/\*)+\"+\s?(?:--|#|\\/\*|{)?)|(?:\"\s*or[\w\s-]+\s*[+<>=(),-]\s*[\d\"])|(?:\"\s*[^\w\s]?=\s*\")|(?:\"\W*[+=]+\W*\")|(?:\"\s*[!=|][\d\s!=+-]+.*[\"(].*$)|(?:\"\s*[!=|][\d\s!=]+.*\d+$)|(?:\"\s*like\W+[\w\"(])|(?:\sis\s*0\W)|(?:where\s[\s\w\.,-]+\s=)|(?:\"[<>~]+\")""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def sql_authentication_2(request) -> RiskLevels:
        return RiskLevels.CRITICAL \
            if re.search(r"""(?:union\s*(?:all|distinct|[(!@]*)\s*[([]*\s*select)|(?:\w+\s+like\s+\")|(?:like\s * \"\%)|(?:\"\s*like\W*[\"\d])|(?:\"\s*(?:n?and|x?or|not |\|\||\&\&)\s+[\s\w]+=\s*\w+\s*having)|(?:\"\s*\*\s*\w+\W+\")|(?:\"\s*[^?\w\s=.,;)(]+\s*[(@\"]*\s*\w+\W+\w)|(?:select\s*[\[\]()\s\w\.,\"-]+from)|(?:find_in_set\s*\()""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def sql_authentication_3(request) -> RiskLevels:
        return RiskLevels.CRITICAL \
            if re.search(r"""(?:in\s*\(+\s*select)|(?:(?:n?and|x?or|not |\|\||\&\&)\s+[\s\w+]+(?:regexp\s*\(|sounds\s+like\s*\"|[=\d]+x))|(\"\s*\d\s*(?:--|#))|(?:\"[%&<>^=]+\d\s*(=|or))|(?:\"\W+[\w+-]+\s*=\s*\d\W+\")|(?:\"\s*is\s*\d.+\"?\w)|(?:\"\|?[\w-]{3,}[^\w\s.,]+\")|(?:\"\s*is\s*[\d.]+\s*\W.*\")""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def concatenated_sql(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""(?:[\d\W]\s+as\s*[\"\w]+\s*from)|(?:^[\W\d]+\s*(?:union|select|create|rename|truncate|load|alter|delete|update|insert|desc))|(?:(?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s+(?:(?:group_)concat|char|load_file)\s?\(?)|(?:end\s*\);)|(\"\s+regexp\W)|(?:[\s(]load_file\s*\()""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def chained_sql_injection_1(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""(?:@.+=\s*\(\s*select)|(?:\d+\s*or\s*\d+\s*[\-+])|(?:\\/\w+;?\s+(?:having|and|or|select)\W)|(?:\d\s+group\s+by.+\()|(?:(?:;|#|--)\s*(?:drop|alter))|(?:(?:;|#|--)\s*(?:update|insert)\s*\w{2,})|(?:[^\w]SET\s*@\w+)|(?:(?:n?and|x?or|not |\|\||\&\&)[\s(]+\w+[\s)]*[!=+]+[\s\d]*[\"=()])""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def chained_sql_injection_2(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""(?:\"\s+and\s*=\W)|(?:\(\s*select\s*\w+\s*\()|(?:\*\\/from)|(?:\+\s*\d+\s*\+\s*@)|(?:\w\"\s*(?:[-+=|@]+\s*)+[\d(])|(?:coalesce\s*\(|@@\w+\s*[^\w\s])|(?:\W!+\"\w)|(?:\";\s*(?:if|while|begin))|(?:\"[\s\d]+=\s*\d)|(?:order\s+by\s+if\w*\s*\()|(?:[\s(]+case\d*\W.+[tw]hen[\s(])""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def benchmark_and(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""(?:(select|;)\s+(?:benchmark|if|sleep)\s*?\(\s*\(?\s*\w+)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def udf_injection(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""(?:create\s+function\s+\w+\s+returns)|(?:;\s*(?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s*[\[(]?\w{2,})""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def charset_switch(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""(?:alter\s*\w+.*character\s+set\s+\w+)|(\";\s*waitfor\s+time\s+\")|(?:\";.*:\s*goto)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def and_postgre_sql(request) -> RiskLevels:
        return RiskLevels.CRITICAL \
            if re.search(r"""(?:procedure\s+analyse\s*\()|(?:;\s*(declare|open)\s+[\w-]+)|(?:create\s+(procedure|function)\s*\w+\s*\(\s*\)\s*-)|(?:declare[^\w]+[@#]\s*\w+)|(exec\s*\(\s*@)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def pg_sleep_injection(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""(?:select\s*pg_sleep)|(?:waitfor\s*delay\s?\"+\s?\d)|(?:;\s*shutdown\s*(?:;|--|#|\\/\*|{))""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def code_execution(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""(?:\sexec\s+xp_cmdshell)|(?:\"\s*!\s*[\"\w])|(?:from\W+information_schema\W)|(?:(?:(?:current_)?user|database|schema|connection_id)\s*\([^\)]*)|(?:\";?\s*(?:select|union|having)\s*[^\s])|(?:\wiif\s*\()|(?:exec\s+master\.)|(?:union select @)|(?:union[\w(\s]*select)|(?:select.*\w?user\()|(?:into[\s+]+(?:dump|out)file\s*\")""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def against_merge(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""(?:merge.*using\s*\()|(execute\s*immediate\s*\")|(?:\W+\d*\s*having\s*[^\s\-])|(?:match\s*[\w(),+-]+\s*against\s*\()""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def comment_space_obfuscated_injections(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""(?:,.*[)\da-f\"]\"(?:\".*\"|\Z|[^\"]+))|(?:\Wselect.+\W*from)|((?:select|create|rename|truncate|load|alter|delete|update|insert|desc)\s*\(\s*space\s*\()""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def injection_attempts_1(request) -> RiskLevels:
        return RiskLevels.CRITICAL \
            if re.search(r"""(?:@[\w-]+\s*\()|(?:]\s*\(\s*[\"!]\s*\w)|(?:<[?%](?:php)?.*(?:[?%]>)?)|(?:;[\s\w|]*\$\w+\s*=)|(?:\$\w+\s*=(?:(?:\s*\$?\w+\s*[(;])|\s*\".*\"))|(?:;\s*\{\W*\w+\s*\()""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def injection_attempts_2(request) -> RiskLevels:
        return RiskLevels.CRITICAL \
            if re.search(r"""(?:(?:[;]+|(<[?%](?:php)?)).*(?:define|eval|file_get_contents|include|require|require_once|set|shell_exec|phpinfo|system|passthru|preg_\w+|execute)\s*[\"(@])""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def injection_attempts_3(request) -> RiskLevels:
        return RiskLevels.CRITICAL \
            if re.search(r"""(?:(?:[;]+|(<[?%](?:php)?)).*[^\w](?:echo|print|print_r|var_dump|[fp]open))|(?:;\s*rm\s+-\w+\s+)|(?:;.*{.*\$\w+\s*=)|(?:\$\w+\s*\[\]\s*=\s*)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def function_declarations(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""(?:function[^(]*\([^)]*\))|(?:(?:delete|void|throw|instanceof|new|typeof)[^\w.]+\w+\s*[([])|([)\]]\s*\.\s*\w+\s*=)|(?:\(\s*new\s+\w+\s*\)\.)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def mail_header(request) -> RiskLevels:
        return RiskLevels.MODERATE if re.search(r"""(?:[\w.-]+@[\w.-]+%(?:[01][\db-ce-f])+\w+:)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def echo_shellcode(request) -> RiskLevels:
        return RiskLevels.MODERATE if re.search(r"""(?:\.pl\?\w+=\w?\|\w+;)|(?:\|\(\w+=\*)|(?:\*\s*\)+\s*;)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def xss_dos(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""(?:(^|\W)const\s+[\w\-]+\s*=)|(?:(?:do|for|while)\s*\([^;]+;+\))|(?:(?:^|\W)on\w+\s*=[\w\W]*(?:on\w+|alert|eval|print|confirm|prompt))|(?:groups=\d+\(\w+\))|(?:(.)\1{128,})""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def attack_vectors(request) -> RiskLevels:
        return RiskLevels.CRITICAL \
            if re.search(r"""(?:\({2,}\+{2,}:{2,})|(?:\({2,}\+{2,}:+)|(?:\({3,}\++:{2,})|(?:\$\[!!!\])""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def vbscript_injection(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""(?:(?:msgbox|eval)\s*\+|(?:language\s*=\*vbscript))""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def mongo_db_sql(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""(?:\[\$(?:ne|eq|lte?|gte?|n?in|mod|all|size|exists|type|slice|or)\])""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def attribute_injection(request) -> RiskLevels:
        return RiskLevels.MODERATE \
            if re.search(r"""(?:[\s\d\\/\"]+(?:on\w+|style|poster|background)=[$\"\w])|(?:-type\s*:\s*multipart)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def sqli_tests(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""(?:(sleep\((\s*)(\d*)(\s*)\)|benchmark\((.*)\,(.*)\)))""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def is_trying(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""(?:(\%SYSTEMROOT\%))""", request) else RiskLevels.NO_RISK

    @staticmethod
    def a_format(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""(?:(((.*)\%[c|d|i|e|f|g|o|s|u|x|p|n]){8}))""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def basic_sql(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""(?:(union(.*)select(.*)from))""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def integer_overflow(request) -> RiskLevels:
        return RiskLevels.SLIGHT \
            if re.search(r"""(?:^(-0000023456|4294967295|4294967296|2147483648|2147483647|0000012345|-2147483648|-2147483649|0000023456|2.2250738585072007e-308|1e309)$)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def comment_filter(request) -> RiskLevels:
        return RiskLevels.SLIGHT if re.search(r"""(?:%23.*?%0a)""", request) else RiskLevels.NO_RISK
