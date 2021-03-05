FROM python:3

# Main Files
ADD waf_waf.py ./waf_waf.py
ADD cli.py ./cli.py
ADD run.sh ./run.sh
ADD run_demo.sh ./run_demo.sh
ADD README.md ./README.md

# Detective Files
ADD detective/detective.py detective/detective.py
ADD detective/__init__.py detective/__init__.py
ADD detective/toolbox/assistant.py detective/toolbox/assistant.py
ADD detective/toolbox/__init__.py detective/toolbox/__init__.py
ADD detective/toolbox/magnifying_glass.py detective/toolbox/magnifying_glass.py
ADD detective/toolbox/risk_levels.py detective/toolbox/risk_levels.py
ADD detective/toolbox/lenses/__init__.py detective/toolbox/lenses/__init__.py
ADD detective/toolbox/lenses/general/basic_checks.py detective/toolbox/lenses/general/basic_checks.py
ADD detective/toolbox/lenses/general/advanced_checks.py detective/toolbox/lenses/general/advanced_checks.py
ADD detective/toolbox/lenses/general/__init__.py detective/toolbox/lenses/general/__init__.py
ADD detective/toolbox/lenses/general/info.py detective/toolbox/lenses/general/info.py
ADD detective/toolbox/lenses/local_file_inclusion/basic_checks.py detective/toolbox/lenses/local_file_inclusion/basic_checks.py
ADD detective/toolbox/lenses/local_file_inclusion/advanced_checks.py detective/toolbox/lenses/local_file_inclusion/advanced_checks.py
ADD detective/toolbox/lenses/local_file_inclusion/__init__.py detective/toolbox/lenses/local_file_inclusion/__init__.py
ADD detective/toolbox/lenses/local_file_inclusion/info.py detective/toolbox/lenses/local_file_inclusion/info.py
ADD detective/toolbox/lenses/command_injection/basic_checks.py detective/toolbox/lenses/command_injection/basic_checks.py
ADD detective/toolbox/lenses/command_injection/advanced_checks.py detective/toolbox/lenses/command_injection/advanced_checks.py
ADD detective/toolbox/lenses/command_injection/__init__.py detective/toolbox/lenses/command_injection/__init__.py
ADD detective/toolbox/lenses/command_injection/info.py detective/toolbox/lenses/command_injection/info.py
ADD detective/toolbox/lenses/remote_file_inclusion/basic_checks.py detective/toolbox/lenses/remote_file_inclusion/basic_checks.py
ADD detective/toolbox/lenses/remote_file_inclusion/advanced_checks.py detective/toolbox/lenses/remote_file_inclusion/advanced_checks.py
ADD detective/toolbox/lenses/remote_file_inclusion/__init__.py detective/toolbox/lenses/remote_file_inclusion/__init__.py
ADD detective/toolbox/lenses/remote_file_inclusion/info.py detective/toolbox/lenses/remote_file_inclusion/info.py
ADD detective/toolbox/lenses/sql_injection/basic_checks.py detective/toolbox/lenses/sql_injection/basic_checks.py
ADD detective/toolbox/lenses/sql_injection/advanced_checks.py detective/toolbox/lenses/sql_injection/advanced_checks.py
ADD detective/toolbox/lenses/sql_injection/__init__.py detective/toolbox/lenses/sql_injection/__init__.py
ADD detective/toolbox/lenses/sql_injection/info.py detective/toolbox/lenses/sql_injection/info.py
ADD detective/toolbox/lenses/xss/basic_checks.py detective/toolbox/lenses/xss/basic_checks.py
ADD detective/toolbox/lenses/xss/advanced_checks.py detective/toolbox/lenses/xss/advanced_checks.py
ADD detective/toolbox/lenses/xss/__init__.py detective/toolbox/lenses/xss/__init__.py
ADD detective/toolbox/lenses/xss/info.py detective/toolbox/lenses/xss/info.py
ADD detective/toolbox/lenses/xxe/basic_checks.py detective/toolbox/lenses/xxe/basic_checks.py
ADD detective/toolbox/lenses/xxe/advanced_checks.py detective/toolbox/lenses/xxe/advanced_checks.py
ADD detective/toolbox/lenses/xxe/__init__.py detective/toolbox/lenses/xxe/__init__.py
ADD detective/toolbox/lenses/xxe/info.py detective/toolbox/lenses/xxe/info.py
ADD detective/toolbox/brute_force/detector.py detective/toolbox/brute_force/detector.py
ADD detective/toolbox/brute_force/captcha_implementer.py detective/toolbox/brute_force/captcha_implementer.py
ADD detective/toolbox/brute_force/captcha.txt detective/toolbox/brute_force/captcha.txt
ADD detective/toolbox/brute_force/__init__.py detective/toolbox/brute_force/__init__.py
ADD detective/toolbox/brute_force/brute_force_configuration.toml detective/toolbox/brute_force/brute_force_configuration.toml
ADD detective/attacks_logger/logger.py detective/attacks_logger/logger.py
ADD detective/attacks_logger/__init__.py detective/attacks_logger/__init__.py

# WAF Data Files
ADD waf_data/warning_message.txt waf_data/warning_message.txt

# CLI Files
ADD command_line_interface/menu.py command_line_interface/menu.py
ADD command_line_interface/main_menu.py command_line_interface/main_menu.py
ADD command_line_interface/email_manager.py command_line_interface/email_manager.py
ADD command_line_interface/__init__.py command_line_interface/__init__.py
ADD command_line_interface/network_scanner/network_scanner.py command_line_interface/network_scanner/network_scanner.py
ADD command_line_interface/network_scanner/scan_functions.py command_line_interface/network_scanner/scan_functions.py
ADD command_line_interface/network_scanner/reporter.py command_line_interface/network_scanner/reporter.py
ADD command_line_interface/network_scanner/loader.py command_line_interface/network_scanner/loader.py
ADD command_line_interface/network_scanner/password_engines.py command_line_interface/network_scanner/password_engines.py
ADD command_line_interface/network_scanner/__init__.py command_line_interface/network_scanner/__init__.py
ADD command_line_interface/network_scanner/runner.py command_line_interface/network_scanner/runner.py
ADD command_line_interface/network_scanner/data/logs command_line_interface/network_scanner/data/logs
ADD command_line_interface/network_scanner/data/vulnerabilities_info.py command_line_interface/network_scanner/data/vulnerabilities_info.py
ADD command_line_interface/network_scanner/data/files/network_passwords.txt command_line_interface/network_scanner/data/files/network_passwords.txt
ADD command_line_interface/network_scanner/data/files/router_usernames.txt command_line_interface/network_scanner/data/files/router_usernames.txt
ADD command_line_interface/network_scanner/data/files/router_passwords.txt command_line_interface/network_scanner/data/files/router_passwords.txt
ADD command_line_interface/network_scanner/data/files/common_ssids.txt command_line_interface/network_scanner/data/files/common_ssids.txt

# Manual Files
ADD manual/executing_info.md manual/executing_info.md

# Miscellaneous Files
ADD misc/colors.py misc/colors.py
ADD misc/logo.png misc/logo.png
ADD misc/__init__.py misc/__init__.py

# Logger Files
ADD logger/data/logs logger/data/logs
ADD logger/data/graphs logger/data/graphs
ADD logger/graph_handler.py logger/graph_handler.py
ADD logger/email_sender.py logger/email_sender.py
ADD logger/__init__.py logger/__init__.py
ADD logger/log_composer.py logger/log_composer.py
ADD logger/data/user_emails.toml logger/data/user_emails.toml
ADD logger/data/bot_email.toml logger/data/bot_email.toml
ADD logger/data/fonts/calibri_light.ttf logger/data/fonts/calibri_light.ttf
ADD logger/data/fonts/calibri_bold.ttf logger/data/fonts/calibri_bold.ttf
ADD logger/data/images/background.jpg logger/data/images/background.jpg

# Installation Commands
RUN apt-get update
RUN apt-get -y install network-manager
RUN apt-get -y install vim
RUN pip3 install mitmproxy
RUN pip3 install toml
RUN pip3 install curtsies
RUN pip3 install matplotlib
RUN pip3 install fpdf

# Automatic Run
CMD ["./run.sh"]
