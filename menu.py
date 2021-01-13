import network_scanner
from curtsies import Input
import os


class Menu:

    def __init__(self):
        self.OKBLUE = '\033[94m'
        self.WARNING = '\033[93m'
        self.exit = 0
        self.menu = []
        self.functions = []
        self.controller = []

    @staticmethod
    def start_scanning():
        print('Start Scanning...')
        scanner = network_scanner.NetworkScanner()
        scanner.scan()

    @staticmethod
    def manage_mails():
        print('Manage mail option')

    @staticmethod
    def clear():
        os.system("clear")

    @staticmethod
    def print_help():
        print("Our project can couple of useful staff for your server\n"
              "Our WAF - web application firewall, runs from the background and protect your server\n"
              "from web attacks and hackers. Moreover, our tool can scan your network and see if its safe\n"
              "Also, every 24 hours (day) our WAF will send to your email log of all the attacks it blocked\n"
              "You have the option to see the current mails that the WAF gonna send to them the log, or even add mail or remove mail from the list\n"
              "This is an open source project, if you would like to see the source, enter to the link below:\n"
              "https://gitlab.com/magshimim-markez-2021/10/1003/pardes-hana-1003-waf\n")

    def add_menu(self, menu, function):
        self.menu.append(menu)
        self.functions.append(function)
        if len(self.controller) == 0:
            self.controller.append(1)
        else:
            self.controller.append(0)

    def start_menu(self):
        self.add_menu('1. Start the network scanning', self.start_scanning)
        self.add_menu('2. Manage your emails configuration file', self.manage_mails)
        self.add_menu('3. Get help and explanation about our tool', self.print_help)
        self.add_menu('4. Clear the screen', self.clear)
        self.add_menu('Exit', 'exit')
        for menu_item in range(len(self.menu)):
            if self.controller[menu_item] == 1:
                print(self.WARNING + self.menu[menu_item])
            else:
                print(self.OKBLUE + self.menu[menu_item])

    def handle_menu(self, event):
        if event == "'KEY_DOWN'":
            if self.controller.index(1) != (len(self.controller) - 1):
                self.controller.insert(0,0)
                self.controller.pop()
        elif event == "'KEY_UP'":
            if self.controller.index(1) != 0:
                self.controller.append(0)
                self.controller.pop(0)
        for menu_item in range(len(self.menu)): #printing all menu items with the right color
            if self.controller[menu_item] == 1:
                print(self.WARNING + self.menu[menu_item])
            else:
                print(self.OKBLUE + self.menu[menu_item])
        if event == "'\\n'":
            if self.functions[self.controller.index(1)] == 'exit':
                self.exit = True
                return
            elif self.functions[self.controller.index(1)].__name__ == "clear":
                self.functions[self.controller.index(1)]()
                self.handle_menu("")
            else:
                self.functions[self.controller.index(1)]()


def main():
    main_menu = Menu()
    main_menu.start_menu()
    with Input(keynames='curses') as input_generator:
        for user_input in input_generator:
            main_menu.handle_menu(repr(user_input))
            if main_menu.exit:
                break


if __name__ == "__main__":
    main()
