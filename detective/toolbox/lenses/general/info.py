category = "General"

general_info = "The detection methods of the following attacks were copied from 'PHPIDS'.\n" \
               "We use those methods as general detections for various attack types.\n"

deep_info = {
    "breaking_injections": "* Breaking Injections: We detected attribute breaking injections\n  "
                           "including obfuscated attributes.\n",

    "html_breaking_injections": "* HTML Breaking Injections: We detected html breaking injections\n  "
                                "including whitespace attacks.\n",

    "attribute_breaking_injections": "* Attribute Breaking Injections: We detected attribute\n  "
                                     "breaking injections including whitespace attacks.\n",

    "attribute_breaking": "* Attribute Breaking: We detected unquoted\n  "
                          "attribute breaking injections.\n",

    "name_json": "* Name JSON: We detected url-, name-, JSON,\n  "
                 "and referrer-contained payload attacks.\n",

    "xss_payload": "* XSS Payload: We detected hash-contained xss payload attacks,\n  "
                   "setter usage and property overloading.\n",

    "contained_xss": "* Contained XSS: We detected self contained xss via with(),\n  "
                     "common loops and regex to string conversion.\n",

    "with_ternary": "* With Ternary: We detected JavaScript with(), ternary operators\n  "
                    "and XML predicate attacks.\n",

    "javascript_functions": "JavaScript Functions: We detected self-executing JavaScript functions.\n",

    "ie_octal": "* IE octal: We detected IE octal, hex and unicode entities.\n",

    "directory_traversal": "* Directory Traversal: We detected basic directory traversal.\n",

    "directory_and": "* Directory And: We detected specific directory and path traversal.\n",

    "inclusion_attempts": "* Inclusion Attempts: We detected etc/passwd inclusion attempts.\n",

    "encoded_unicode": "* Encoded Unicode: We detected halfwidth/fullwidth\n  "
                       "encoded unicode HTML breaking attempts.\n",

    "includes_vbscript_jscript": "* Includes VBScript JScript: We detected possible includes,\n  "
                                 "VBScript/JavaScript encoded and packed functions.\n",

    "dom_miscellaneous_properties": "* DOM Miscellaneous Properties: We detected JavaScript\n  "
                                    "DOM/miscellaneous properties and methods.\n",

    "includes_and": "* Includes And: We detected possible includes and typical script methods.\n",

    "object_properties": "* Object Properties: We detected JavaScript object properties and methods.\n",

    "array_properties": "* Array Properties: We detected JavaScript array properties and methods.\n",

    "string_properties": "* String Properties: We detected JavaScript string properties and methods.\n",

    "language_constructs": "* Language Constructs: We detected JavaScript language constructs.\n",

    "basic_xss": "* Basic XSS: We detected very basic XSS probings.\n",

    "xss_probings": "* XSS Probings: We detected advanced XSS probings via Script(),\n  "
                    "RexExp, constructors and XML namespaces.\n",

    "location_document_property": "* Location Document Property: We detected JavaScript\n  "
                                  "location/document property access and window access obfuscation.\n",

    "obfuscated_javascript": "* Obfuscated JavaScript: We detected basic obfuscated JavaScript script injections.\n",

    "javascript_script": "* JavaScript Script: We detected obfuscated JavaScript script injections.\n",

    "cookie_stealing": "* Cookie Stealing: We detected JavaScript cookie stealing\n  "
                       "and redirection attempts.\n",

    "url_injections": "* URL Injections: We detected URL injections,\n  "
                      "VBS injections and common URI schemes.\n",

    "firefox_url_injections": "* Firefox URL Injections: We detected IE firefox URL injections,\n  "
                             "cache poisoning attempts and local file inclusion/execution.\n",

    "and_behavior": "* And Behavior: We detected bindings and behavior injections.\n",

    "xss_concatenation_1": "* XSS Concatenation: We detected common XSS concatenation patterns.\n",

    "xss_concatenation_2": "* XSS Concatenation: We detected common XSS concatenation patterns.\n",

    "event_handlers": "* Event Handlers: We detected possible event handlers.\n",

    "script_tags": "* Script Tags: We detected obfuscated script tags and XML wrapped HTML.\n",

    "in_closing": "* In Closing: We detected attributes in closing tags\n  "
                  "and conditional compilation tokens.\n",

    "comment_types": "* Comment Types: We detected common comment types.\n",

    "href_injections": "* href Injections: We detected base href injections\n  "
                       "and XML entity injections.\n",

    "malicious_html": "* Malicious HTML: We detected possibly malicious html\n  "
                      "elements including some attributes.\n",

    "and_other": "* And Other: We detected null bytes and other dangerous characters.\n",

    "comments_conditions": "* Comments Conditions: We detected MySQL comments,\n  "
                           "conditions and ch(a)r injections.\n",

    "conditional_sql_injection": "* Conditional SQL Injection: We detected conditional\n  "
                                 "SQL injection attempts.\n",

    "classic_sql_injection_1": "* Classic SQL Injection: We detected classic\n  "
                               "SQL injection probings.\n",

    "classic_sql_injection_2": "* Classic SQL Injection: We detected classic\n  "
                               "SQL injection probings.\n",

    "sql_authentication_1": "* SQL Authentication: We detected basic\n  "
                            "SQL authentication bypass attempts.\n",

    "sql_authentication_2": "* SQL Authentication: We detected basic\n  "
                            "SQL authentication bypass attempts.\n",

    "sql_authentication_3": "* SQL Authentication: We detected basic\n  "
                            "SQL authentication bypass attempts.\n",

    "concatenated_sql": "* Concatenated SQL: We detected concatenated basic\n  "
                        "SQL injection and SQLLFI attempts.\n",

    "chained_sql_injection_1": "* Chained SQL Injection: We detected chained\n  "
                               "SQL injection attempts.\n",

    "chained_sql_injection_2": "* Chained SQL Injection: We detected chained\n  "
                               "SQL injection attempts.\n",

    "benchmark_and": "* Benchmark And: We detected SQL benchmark and sleep\n  "
                     "injection attempts including conditional queries.\n",

    "udf_injection": "* UDF Injection: We detected MySQL UDF injection\n  "
                     "and other data/structure manipulation attempts.\n",

    "charset_switch": "* Charset Switch: We detected MySQL charset\n  "
                      "switch and MSSQL DoS attempts.\n",

    "and_postgre_sql": "* And Postgre SQL: We detected MySQL and\n  "
                       "PostgreSQL stored procedure/function injections.\n",

    "pg_sleep_injection": "* pg_sleep Injection: We detected Postgres pg_sleep injection,\n  "
                          "wait for delay attacks and database shutdown attempts.\n",

    "code_execution": "* Code Execution: We detected MSSQL code execution\n  "
                      "and information gathering attempts.\n",

    "against_merge": "* AGAINST MERGE: We detected MATCH AGAINST,\n  "
                     "MERGE, EXECUTE IMMEDIATE and HAVING injections.\n",

    "comment_space_obfuscated_injections": "* Comment Space Obfuscated Injections: We detected MySQL\n  "
                                           "comment-/space-obfuscated injections and backtick termination.\n",

    "injection_attempts_1": "* Injection Attempts: We detected code injection attempts.\n",

    "injection_attempts_2": "* Injection Attempts: We detected code injection attempts.\n",

    "injection_attempts_3": "* Injection Attempts: We detected code injection attempts.\n",

    "function_declarations": "* Function Declarations: We detected common function\n  "
                             "declarations and special JavaScript operators.\n",

    "mail_header": "* Mail Header: We detected common mail header injections.\n",

    "echo_shellcode": "* Echo Shellcode: We detected perl echo shellcode\n  "
                      "injection and LDAP vectors.\n",

    "xss_dos": "* XSS DoS: We detected basic XSS DoS attempts.\n",

    "attack_vectors": "* Attack Vectors: We detected unknown attack vectors\n  "
                      "based on 'PHPIDS' Centrifuge detection.\n",

    "vbscript_injection": "* VBScript Injection: We detected basic VBScript injection attempts.\n",

    "mongo_db_sql": "* MongoDB SQL: We detected basic MongoDB SQL injection attempts.\n",

    "attribute_injection": "* Attribute Injection: We detected malicious attribute\n  "
                           "injection attempts and MHTML attacks.\n",

    "sqli_tests": "* SQL Injection Tests: We detected blind SQL Injection\n  "
                  "tests using sleep() or benchmark().\n",

    "is_trying": "* Is Trying: We detected an attacker who tried to locate a file to read or write.\n",

    "a_format": "* A Format: We detected an A Format string attack.\n",

    "basic_sql": "* Basic SQL: We detected common attack strings\n  "
                 "for mysql, oracle and others.\n",

    "integer_overflow": "* Integer Overflow: We detected integer overflow attacks.\n  "
                        "These are taken from skip fish, except 2.2250738585072007e-308\n  "
                        "is the 'magic number' crash.\n",

    "comment_filter": "* Comment Filter: We detected SQL comment filter evasion.\n"
}

links_for_info = "For more information about 'PHPIDS', our source for the general detections, " \
                 "check the following link:\n" \
                 "https://github.com/PHPIDS/PHPIDS/blob/master/lib/IDS/default_filter.json"
