"""python classes have few simple rules:
1 all function need to get the param self, that is the param
that represent the class object
2 all the properties in python class are public, so you can get to them just
like: onject_name.property, and also can modify them. but still, we want to create set functions
3 there are properties that we can define, that will be equal for all instances of the class
4 to create subclass just type the syntax: class className(upperClass):
5 with the super() function, you can go to the upperClass functions"""
class BankAccount:
    bank_name = "PayPy"
    def __init__(self, name, balance=0):
        self._balance = balance
        self._name = name
    def deposit(self, amount):
        self._balance += amount

    def withdraw(self, amount):
        self._balance -= amount

    def print_balance(self):
        print("current balance is: ", self._balance)
    def greet(self):
        print("Welcome ", self._name)
class animal:
    zoo_name = "Hayaton"
    def __init__(self, name, hunger=0):
        self._hunger = hunger
        self._name = name
    def is_hungry(self):
        return self._hunger > 0
    def feed(self):
        self._hunger -= 1
    def get_name(self):
        return self._name
    def get_type(self):
        return "animal"
    def talk(self, content):
        return content
class dog(animal):
    def get_type(self):
        return "dog"
    def talk(self):
        return super().talk("woof woof")
    def fetch_stick(self):
        return "There You Go, Sir!"
class cat(animal):
    def get_type(self):
        return "cat"
    def talk(self):
        return super().talk("meow")
    def chase_laser(self):
        return "Meeeow"
class skunk(animal):
    def __init__(self, name, hunger=0, stink_count=6):
        super().__init__(name, hunger)
        self._stinck_count = stink_count
    def get_type(self):
        return "skunk"
    def talk(self):
        return super().talk("tsssss")
    def stink(self):
        return "Dir Lord"
class unicorn(animal):
    def get_type(self):
        return "unicorn"
    def talk(self):
        return super().talk("Good Day, Darling")
    def sing(self):
        return "Im Not Your Toy!"
class dragon(animal):
    def get_type(self):
        return "dragon"
    def talk(self):
        return super().talk("Raaaawr")
    def fire_breath(self):
        return "$@#$#@$"
    def __init__(self, name, hunger=0, color="Green"):
        super().__init__(name, hunger)
        self._color = color

def main():
    zoo_lst = [dog("Brownie", 10), cat("Zelda", 3), skunk("stinky", 0), unicorn("Keith", 7), dragon("Lizzy", 1450), dog("Doggo", 80), cat("Kitty", 80), skunk("Stinky JR.", 80), unicorn("Clair", 80), dragon("McFly", 80)]
    for animal in zoo_lst:
        while animal.is_hungry():
            animal.feed()
        print(animal.get_type(), animal.get_name())
        print(animal.talk())
        if animal.get_type() == "dog":
            print(animal.fetch_stick())
        elif animal.get_type() == "cat":
            print(animal.chase_laser())
        elif animal.get_type() == "skunk":
            print(animal.stink())
        elif animal.get_type() == "unicorn":
            print(animal.sing())
        elif animal.get_type() == "dragon":
            print(animal.fire_breath())
    """my_account = BankAccount("Noam")
    my_account.greet()
    dad_account = BankAccount("Gadi")
    my_account.withdraw(700)
    my_account.deposit(1200)
    my_account.print_balance()"""

if __name__ == '__main__':
    main()

