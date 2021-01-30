category = "Local File Inclusion"

general_info = "Local file inclusion (LFI) is the process of including files,\n" \
               "that are already locally present on the server, through the exploiting of vulnerable inclusion\n" \
               "procedures implemented in the application. This vulnerability occurs, for example,\n" \
               "when a page receives as input the path to the file that has to be included, and this input\n" \
               "is not properly sanitized, allowing directory traversal characters (such as dot-dot-slash)\n" \
               "to be injected."

deep_info = {
    "etc_files": "* /etc Files: The etc path contains a lot files, and also sensitive\n  ones "
                 "like passwd, and others. Many networking\n  configuration files are in /etc as well. "
                 "An attacker\n  can get information about the server in this path.\n",

    "home_files": "* /home Files: The home directory, also called a login directory, \n  is the directory on Unix-like "
                  "operating systems that serves as the\n  repository for a user's personal files, "
                  "directories and programs.\n  It is also the directory that a user will be lead to "
                  "after logging into the system.\n",

    "root_files": "* /root Files: The / directory known as the root directory sits on the\n  top of the file "
                  "system hierarchy. It means that from the\n  access to the root directory, "
                  "an attacker can\n  access all the files on the server.\n",

    "proc_files": "* /proc Files: The proc directory is a special directory that\n  holds all the details about "
                  "your Linux system, including its kernel,\n  processes, and configuration parameters. "
                  "A potential attacker can access the information\n  within this path in order "
                  "to get data about the server processes.\n",

    "var_files": "* /var Files: The var directory contains things that are prone to change,\n  such as websites, "
                 "temporary files (/var/tmp) and databases.\n  The var directory contains useful "
                 "information and data that is used by the server.\n",

    "information_files": "* Information Files: Be careful! if you see this message it means that a user\n  "
                         "had probably tried to access some very sensitive files,\n  like PHP configurations or "
                         "authorized keys for the server.\n",

    "windows_files": "* Windows Files: In the windows directory you can find some really\n  important files that "
                     "belongs to the operating system in windows.\n  These files should not reach the attacker "
                     "because they will\n  give him a lot of information about the server's environment.\n",

    "sensitive_windows_files": "* Sensitive Windows Files: Be careful! if you see this message\n  it means that a "
                               "user had probably tried to access some\n  very sensitive files in your server.\n",

    "program_files": "* Program Files: This directory is a standard folder in Microsoft Windows\n  operating systems. "
                     "Applications that are not part of the operating system are\n  conventionally installed in there. "
                     "This path might contain files that belong to the server.\n",

    "windows_variables": "* Windows Variables: An environment variable is a dynamic-named value\n  that can affect the "
                         "way running processes will behave on a computer.\n  They are part of the environment in "
                         "which a process runs.\n  An access to these variables can give a user useful information\n  "
                         "and even permissions to edit the process on the server.\n",

    "php_files": "* PHP Files: This path contains all the PHP configuration files, and also information\n  "
                 "about the PHP version and the server settings.\n",

    "php_functions": "* PHP Functions: Functions that can modify some PHP content on the server\n  "
                     "if its read or write.\n",

    "php_expect_wrapper": "* PHP Expect Wrapper: A module that can run a terminal command via\n  "
                          "the PHP wrapper. You don't want any user to run commands on your machine.\n",

    "php_file_get_put_content": "* PHP file_get/put_contents: This PHP function will get\n  or set contents a file. "
                                "You don't want any user to have access to your files.\n",

    "php_edit_files_function": "* PHP edit_files Function: This PHP function will edit the server's files\n  and it "
                               "can interrupt its running.\n  You don't want any user to have access to your files.\n",

    "php_stream_filter": "* PHP Stream Filter: A final piece of code which may perform operations on data\n  "
                         "as it is being read from or written to a stream.\n  An attacker may use this to "
                         "manipulate your PHP functions on the server side.\n",

    "stream_filter_base64": "* Stream Filter base64: A final piece of code which may perform operations on data\n  "
                            "as it is being read from or written to a stream.\n  An attacker may use this to "
                            "decrypt his path or output.\n",

    "stream_filter_zlib": "* Stream Filter zlib: A final piece of code which may perform operations on data\n  "
                          "as it is being read from or written to a stream.\n  An attacker may use this to "
                          "manipulate your PHP functions on the server side.\n",

    "apache_server_side_inclusion": "* Apache Server Side Inclusion: An attacker can pass through the URL\n  "
                                    "functions he wants the server to execute,\n  like exec, in order to run "
                                    "scripts or to include files.\n",

    "url_encoding_unicode": "* URL Encoding Unicode: An attacker may hide the URL and encode the\n  path of the file "
                            "he tries to access.\n  It is very smart and uncommon, but a possible scenario.\n",

    "local_chrome_files": "* Local Chrome Files: There is option on chrome to see and check the local files.\n  "
                          "The files can provide a user information that seems harmless\n  "
                          "but can be very useful to a potential attacker.\n",

    "malicious_parameters": "* Malicious Parameters: LFI can be achieved via using\n  "
                            "parameters which will either, execute commands on your machine,\n  or include "
                            "malicious files into your system.\n"
}

links_for_info = "For more information about Local File Inclusion, check the following links:\n" \
                 "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application\n" \
                 "_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion\n" \
                 "https://www.acunetix.com/blog/articles/local-file-inclusion-lfi/"
