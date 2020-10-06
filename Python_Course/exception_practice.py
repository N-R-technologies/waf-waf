#all the exceptions possible in the creation of user
import string
class UsernameContainsIllegalCharacter(Exception):
    def __init__(self, pos, character):
        self._pos = pos
        self._character = character

    def __str__(self):
        return "password contains illegal character: " + self._character + " in position " + str(self._pos)

    def get_arg(self):
        return self._arg
class UsernameTooShort(Exception):
    def __init__(self, arg):
        self._arg = arg

    def __str__(self):
        return "username length is too short, it need to be minimum 3 letters when actually contains " + str(len(self._arg))

    def get_arg(self):
        return self._arg

class UsernameTooLong(Exception):
    def __init__(self, arg):
        self._arg = arg

    def __str__(self):
        return "username length is too long, it need to be maximum 16 letters when actually contains " + str(len(self._arg))

    def get_arg(self):
        return self._arg
class PasswordMissingCharacter(Exception):
    def __init__(self, arg):
        self._arg = arg

    def __str__(self):
        return "the password doesnt contains one of the must letters, there isnt any " + self._arg + " character"

    def get_arg(self):
        return self._arg
class PasswordTooShort(Exception):
    def __init__(self, arg):
        self._arg = arg

    def __str__(self):
        return "password length is too short, it need to be minimum 8 letters when actually contains " + str(len(self._arg))

    def get_arg(self):
        return self._arg
class PasswordTooLong(Exception):
    def __init__(self, arg):
        self._arg = arg

    def __str__(self):
        return "password length is too long, it need to be maximum 40 letters when actually contains " + str(len(self._arg))

    def get_arg(self):
        return self._arg
def check_input(username, password):
    try:
        for letter in username:
            if (not letter.isalpha()) and (not letter.isnumeric()) and (not letter == '_'):
                raise UsernameContainsIllegalCharacter(username.index(letter), letter)
        if len(username) < 3:
            raise UsernameTooShort(username)
        if len(username) > 16:
            raise UsernameTooLong(username)
        if len(password) < 8:
            raise PasswordTooShort(password)
        if len(password) > 40:
            raise PasswordTooLong(password)
        one_upper = False
        one_lower = False
        one_num = False
        sign = False
        for letter in password:
            if letter.islower():
                one_lower = True
            elif letter.isupper():
                one_upper = True
            elif letter.isnumeric():
                one_num = True
            elif letter in string.punctuation:
                sign = True
        if not one_upper:
            raise PasswordMissingCharacter("upper")
        if not one_lower:
            raise PasswordMissingCharacter("lower")
        if not one_num:
            raise PasswordMissingCharacter("num")
        if not sign:
            raise PasswordMissingCharacter("punctuation")
    except Exception as e:
        print(e.__str__())
    else:
        print("OK")
def main():
    print("welcome to my website, enter your username and password for register:")
    check_input("A_1", "abcdefghijklmnop")
    check_input("A_1", "ABCDEFGHIJLKMNOP")
    check_input("A_1", "ABCDEFGhijklmnop")
    check_input("A_1", "4BCD3F6h1jk1mn0p")

if __name__ == "__main__":
    main()