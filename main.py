import network_scanner
from curtsies import Input
import mail_manager
from menu import Menu


def start_scanning():
    """
    function start the network scanning
    """
    print('Start Scanning...')
    scanner = network_scanner.NetworkScanner()
    scanner.scan()


def manage_mails():
    """
    function start the manage emails menu
    """
    mail_manager.start_manage_mails()


def print_help():
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


def start_menu(menu):
    """
    function start the main menu of the program
    :param menu: object from class menu that is represent the main menu
    :type menu: class Menu
    :return: None
    """
    menu.add_menu('1. Start the network scanning', start_scanning)
    menu.add_menu('2. Manage your emails configuration file', manage_mails)
    menu.add_menu('3. Get help and explanation about our tool', print_help)
    menu.add_menu('4. Exit or press Q', 'exit')
    for menu_item in range(len(menu.menu)):
        if menu.controller[menu_item] == 1:
            print(menu.WARNING + menu.menu[menu_item])
        else:
            print(menu.OKBLUE + menu.menu[menu_item])
    print("You can press q for quit also if you want")


def main():
    main_menu = Menu()
    start_menu(main_menu)
    with Input(keynames='curses') as input_generator:
        for user_input in input_generator:
            main_menu.clear()
            main_menu.handle_menu(repr(user_input))
            if main_menu.exit:
                break


if __name__ == "__main__":
    main()
