import network_scanner
from curtsies import Input
from mail_manager import MailManager
from menu import Menu


class MainProgram:

    def __init__(self):
        self._main_menu = Menu()

    def _start_scanning(self, router_username, router_password):
        """
        function start the network scanning
        :param router_username: the username of the router
        :param router_password: the password of the router
        :type router_username: str
        :type router_password: str
        """
        print('Start Scanning...')
        self._main_menu.close_input()
        scanner = network_scanner.NetworkScanner()
        scanner.scan(router_username, router_password)

    def _manage_mails(self):
        """
        function start the manage emails menu
        """
        mail_manager = MailManager()
        mail_manager.start_manage_mails()

    def _print_help(self):
        """
        function print info about the program
        """
        print("Our project can couple of useful staff for your server\n"
              "Our WAF - web application firewall, runs from the background and protect your server\n"
              "from web attacks and hackers. Moreover, our tool can scan your network and see if its safe\n"
              "Also, every 24 hours (day) our WAF will send to your email log of all the attacks it blocked\n"
              "You have the option to see the current mails that the WAF gonna send to them the log, or even add mail or remove mail from the list\n"
              "This is an open source project, if you would like to see the source, enter to the link below:\n"
              "https://gitlab.com/magshimim-markez-2021/10/1003/pardes-hana-1003-waf\n")

    def start_menu(self):
        """
        function start the main menu of the program
        :return: None
        """
        self._main_menu.add_menu('1. Start the network scanning', self._call_scan)
        self._main_menu.add_menu('2. Manage your emails configuration file', self._manage_mails)
        self._main_menu.add_menu('3. Get help and explanation about our tool', self._print_help)
        self._main_menu.add_menu('4. Exit or press Q', 'exit')
        for menu_item in range(len(self._main_menu.menu)):
            if self._main_menu.controller[menu_item] == 1:
                print(self._main_menu.WARNING + self._main_menu.menu[menu_item])
            else:
                print(self._main_menu.OKBLUE + self._main_menu.menu[menu_item])
        print("You can press q for quit also if you want")

    def _call_scan(self):
        self._main_menu.get_input(self._start_scanning, "Enter router credentials",
                                  "router's username, if you don't know, leave blank",
                                  "router's password, if you don't know, leave blank")

    def main(self):
        self.start_menu()
        with Input(keynames='curses') as input_generator:
            for user_input in input_generator:
                self._main_menu.clear()
                self._main_menu.handle_menu(repr(user_input))
                if self._main_menu.exit:
                    break


if __name__ == "__main__":
    newTool = MainProgram()
    newTool.main()
