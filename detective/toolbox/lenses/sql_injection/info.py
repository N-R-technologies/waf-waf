category = "SQL Injection"

general_info = "SQL Injection is a web security vulnerability that allows an attacker to interfere with the\n" \
               "queries that an application makes to its database.\n" \
               "It generally allows an attacker to view data that they are not normally able to retrieve.\n" \
               "Also with this the attacker can modify the database or even inject some malicious code to.\n"

deep_info = {
    "cstyle_comment": "* C-Style Comment: The user is trying to add some C-style comments into your SQL query "
                      "maybe in\n  order to delete the information after the comments.\n",

    "find_in_set": "* Find In Set: A Function that returns the position of a string within a list "
                   "of strings.\n  This function is not dangerous for itself, but it is a good indicator "
                   "for whatever someone try to\n  attack the database or get some information about it.\n",

    "master_access": "* Master Access: Master is a scheme table that contains all the information,\n  "
                     "values and indexes about the Table.\n  The attacker can prepare his attack with getting "
                     "some information about the database.\n",

    "user_disclosure": "* User Disclosure: The user table is a global table in every MySQL database,\n  so we make "
                       "sure the attacker doesn't try to access it and get the information about the users.\n",

    "user_info_disclosure": "* User Information Disclosure: pg_user is a specific command that returns"
                            " information about all the\n  users in a specific database, In the wrong "
                            "hands, this information about the users can be dangerous.\n",

    "db_info_disclosure": "* DB Information Disclosure: pg_database stores information about the available "
                          "databases.\n  this information should not reach the attacker.\n",

    "shadow_info_disclosure": "* Shadow Information Disclosure: The view pg_shadow exists for backwards "
                              "compatibility:\n  It emulates a catalog that existed in PostgreSQL.\n  "
                              "This option could be used by an attacker that runs his own catalog.\n",

    "load_file_disclosure": "* Load File Disclosure: Load file function generally reads the file and returns the "
                            "file's content\n  as string. It can be harmful when the user loads some\n  "
                            "important file and then select it with a regular query.\n",

    "load_data_disclosure": "* Load Data Disclosure: The LOAD DATA statement reads rows from a text file into "
                            "a table.\n  An attacker can use this function in order to inject some malicious "
                            "script into the database.\n",

    "information_disclosure": "* Information Disclosure: INFORMATION_SCHEMA provides access to database metadata.\n  "
                              "With this function the attacker can see all the information about the MySQL server,\n  "
                              "such as the name of a database or a table, the data type of a column, "
                              "or access privileges.\n",

    "write_into_outfile": "* Write Into Outfile: This function writes the selected rows to a file, so the attacker "
                          "can write\n  some parts of the database to a specific file and then some how take it.\n",

    "concat_command": "* Concat Command: The concat command is another way for the attacker to check if his injection "
                      "can\n  work. This command is basically concat couple of strings together into one string.\n",

    "blind_benchmark": "* Blind Benchmark: Blind SQL Injections are the types that doesn't shown screen.\n  "
                       "An attacker can reach this goal by the benchmark function which make a delayed response "
                       "only if\n  the injection succeed. Also he doesn't need high privileges for that.\n",

    "blind_sql_sleep": "* Blind SQL Sleep: With this function the attacker can delay the server's response\n  "
                       "and see if his injections can work.\n",

    "blind_tsql": "* Blind TSQL: With this function the attacker can delay the server's response\n  "
                  "and see if his injections can work.\n",

    "sleep_pg_command": "* Sleep PG Command: With this function the attacker can delay the\n  "
                        "server's response and see if his injections can work.\n",

    "length_command": "* Length Command: For themselves, this function is not dangerous at all, but you "
                      "shouldn't let\n  a user enter any kind of function as input.\n  This function returns "
                      "the length of a string.\n",

    "hex_command": "* Hex Command: For themselves, this function is not dangerous at all, but you "
                   "shouldn't let\n  a user enter any kind of function as input.\n  This function decodes "
                   "a decimal-encoded hexadecimal field.\n",

    "base64_command": "* Base64 Command: For themselves, this function is not dangerous at all, but you "
                      "shouldn't let\n  a user enter any kind of function as input.\n  This function returns "
                      "a base64 encoded string based on a given string.\n",

    "oct_command": "* Oct Command: For themselves, this function is not dangerous at all, but you shouldn't let\n  "
                   "a user enter any kind of function as input.\n  "
                   "This function returns the octal value of a decimal number.\n",

    "ord_command": "* Ord Command: For themselves, this function is not dangerous at all, but you shouldn't let a\n  "
                   "user enter any kind of function as input.\n  This function returns the numeric value of the left "
                   "most character of a given string.\n",

    "ascii_command": "* Ascii Command: For themselves, this function is not dangerous at all, "
                     "but you shouldn't let\n  a user enter any kind of function as input.\n  "
                     "This function returns the ASCII value of the first character in given string.\n",

    "bin_command": "* Bin Command: For themselves, this function is not dangerous at all, "
                   "but you shouldn't let\n  a user enter any kind of function as input.\n  "
                   "This function returns a binary representation of a number.\n",

    "char_command": "* Char Command: For themselves, this function is not dangerous at all, but you "
                    "shouldn't let\n  a user enter any kind of function as input.\n  "
                    "This function returns a character based on a given ASCII code.\n",

    "substr_command": "* Substr Command: The substr function is not so dangerous for its self,\n  "
                      "but generally it parses the string that returns from the database.\n  "
                      "The attacker can use it for manipulate the output from the database.\n",

    "user_command": "* User Command: The user function allows the attacker to manipulate the users\n  permissions and "
                    "also see all the existing users in the database\n  and more information about the users.\n",

    "version_command": "* Version Command: The version function seems very nice and harmless but you should"
                       "be careful.\n  The attacker can see the version of the database and this info\n  "
                       "can be very useful for the next steps of the attack.\n",

    "system_variable": "* System Variable: System variables that store information about the running package "
                       "and its objects.\n  This information can be very useful for future attacker.\n",

    "if_command": "* If Command: The if statement can be used to check some conditions in it.\n  "
                  "With that said, an attacker can use this statement to check if the condition is true.\n",

    "ifnull_command": "* Ifnull Command: The if statement can use for check some condition in it.\n  "
                      "With that said, attacker can use this statement to check if the condition is null.\n",

    "case_command": "* Case Command: The case statement checks for each case if its true. Like the if condition,\n  "
                    "the case can show the attacker if the injection works as he expected to.\n",

    "exec_command": "* Execute Command: The exec function is a very dangerous one, you should be careful.\n  "
                    "With this function the user can execute wide range of functions\n  and scripts "
                    "on your server side.\n",

    "create_procedure_command": "* Create Procedure Command: With the create function the attacker can " 
                                "create procedure\n  or function that could run on your database.\n",

    "mongo_db_command": "* Mongo DB Command: The attacker may use some of the common commands in mongoDB, that "
                        "are not so\n  frequent, so it is suspicious he use this characters.\n",

    "db_command": "* DB Command: The DATABASE() function returns the name of the current database.\n  "
                  "This information can help the attacker so it should not reach the attacker.\n",

    "alter": "* Alter: With the alter table function, the attacker can modify the database.\n",

    "exist": "* Exist: The exist function checks if a row or database exist.\n  That can be useful "
             "for a future hacker, in order to set his environment for hacking,\n  and check the "
             "settings of the database.\n",

    "create": "* Create: Create function creates a new row or a database.\n  This can be very dangerous "
              "if the attacker will try to add some malicious code in a row,\n  or even a fake database.\n",

    "update": "* Update: The update command modifies and changes values that appear in the database.\n  "
              "An attacker can put a malicious code in a single row,\n  and then other users "
              "that will run this row will run his virus as well.\n",

    "delete": "* Delete: With the delete function, the user can delete, rows, values and even the database.\n  "
              "that can be vary dangerous for the server.\n",

    "drop": "* Drop: Drop function can delete raw, table and even database,\n  potential hacker can use it for "
            "disabling the whole website.\n  Therefore this command is very dangerous for any database.\n",

    "truncate": "* Truncate: Truncate table deletes a data inside a table.\n  "
                "A hacker can use it for deleting very important information from the\n  database "
                "like registered users.\n",

    "insert": "* Insert: The insert function add row to a database.\n  "
              "A hacker can add some malicious code into the database with this command.\n",

    "select_union": "* Select Union: Function that gets and returns values or raw from a database.\n  "
                    "A user can use it to see secret information, that he shouldn't see "
                    "like credit cards numbers.\n  That function can be very dangerous and it is very "
                    "common among SQL Injection hackers.\n",

    "select_into": "* Select Into: Function that gets and returns values or raw from a database.\n  "
                   "A user can use it to see secret information, that he shouldn't see "
                   "like credit card numbers.\n  That function can be very dangerous and "
                   "it is very common among SQL Injection hackers.\n",

    "select_from": "* Select From: Function that gets and returns values or raw from a database.\n  "
                    "A user can use it to see secret information, that he shouldn't see "
                    "like credit card numbers.\n  That function can be very dangerous and "
                    "it is very common among SQL Injection hackers.\n",

    "or_statement": "* Or: Or is a logical statement that can be very dangerous to your database.\n  "
                    "In order to make any query he wants, the attacker can add an or statement to the "
                    "query\n  that will be always true, like 1=1.\n",

    "grant_revoke": "* Grant/Revoke: The grant or revoke functions are letting the attacker the option "
                    "to manipulate\n  and change the permissions of the database.\n"
}

links_for_info = "For more information about SQL Injection, check the following links:\n" \
                 "https://owasp.org/www-community/attacks/SQL_Injection\n" \
                 "https://portswigger.net/web-security/sql-injection"
