import os
from curtsies import Input
from menu import Menu
import toml
import re


def clear():
    """
    function clear the screen
    """
    os.system("clear")


def add_mail():
    """
    function add one mail to the mails file
    """
    name = input("Enter the name of the owner of the mail address:\n")
    address = input("Enter the mail address:\n")
    exit_flag = False
    while not is_mail_valid(address) or exit_flag:
        print("Your mail address is not valid...")
        print("enter q for quit")
        address = input("Enter the mail address:\n")
        if address.lower() == 'q':
            exit_flag = True
    if exit_flag:
        return
    with open("log_related/data/user_addresses.toml", 'a') as email_file:
        toml.dump({name: address}, email_file)
    email_file.close()


def remove_mail():
    """
    function remove one mail from the mails file
    """
    display_mails()
    exit_flag = False
    user_addresses = toml.load("log_related/data/user_addresses.toml").get("addresses", {})
    mail_index = input("Enter the index of the mail which you want to remove\n")
    while not (mail_index.isdigit() and 1 <= int(mail_index) <= len(user_addresses)) or exit_flag:
        print("Invalid index")
        print("Press q to quit")
        mail_index = input("Enter the index of the mail which you want to remove\n")
        if mail_index.lower() == 'q':
            exit_flag = True
    if exit_flag:
        return
    index = 1
    for name in user_addresses:
        if index == int(mail_index):
            del user_addresses[name]
            break
        index += 1
    with open("log_related/data/user_addresses.toml", 'w') as email_file:
        toml.dump(toml.loads("[addresses]"), email_file)
        for name in user_addresses:
            toml.dump({name: user_addresses[name]}, email_file)
    email_file.close()


def display_mails():
    """
    function display all the emails
    """
    user_addresses = dict()
    if os.path.exists("log_related/data/user_addresses.toml"):
        user_addresses = toml.load("log_related/data/user_addresses.toml").get("addresses", {})
    else:
        open("log_related/data/user_addresses.toml", 'w').close()
    index = 1
    for name in user_addresses:
        print(f"{index}. {name}, {user_addresses[name]}")
        index += 1


def is_mail_valid(mail):
    """
    function checks if the argument mail is valid
    :param mail: the mail to check
    :type mail: str
    :return: True if its valid, otherwise False
    :rtype: bool
    """
    return re.search(r"""^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$""", mail)


def start_manage_mails():
    """
    function start the manage mails menu
    """
    manage_mails = Menu()
    manage_mails.add_menu('1. Display all the emails', display_mails)
    manage_mails.add_menu('2. Delete email from the list', remove_mail)
    manage_mails.add_menu('3. add email to the list', add_mail)
    manage_mails.add_menu('4. Exit', 'exit')
    for menu_item in range(len(manage_mails.menu)):
        if manage_mails.controller[menu_item] == 1:
            print(manage_mails.WARNING + manage_mails.menu[menu_item])
        else:
            print(manage_mails.OKBLUE + manage_mails.menu[menu_item])
    with Input(keynames='curses') as input_generator:
        for user_input in input_generator:
            clear()
            manage_mails.handle_menu(repr(user_input))
            if manage_mails.exit:
                break
