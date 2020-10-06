"""little info about exceptions type:
syntax error: when the complier pass throw the code and see unusual syntax, like ':' missing after condition
runtime error: exceptions that the compiler doesnt see, usually because user input or stuff like that
can be handled by predict the error or check the input
syntax of throw exception manually: raise (key word) Exception_type('description of the exception')
create custom exception: crete the error type that her upperclass is Exception. override the __str__ function
for printing the error"""

class FactorialArgumentError(Exception):
    def __init__(self, arg):
        self._arg = arg
    def __str__(self):
        return "Providid argument " + str(self._arg) + " is not a positive integer"
    def get_arg(self):
        return self._arg
def throw_err_example(n):
    fact = 1
    try:
        if not isinstance(n, int) or n < 0:
            # now we want to throw exception because factorial function isnt working on negative value
            # we also want to throw an exception because it will be hard to handle this problem without it
            raise FactorialArgumentError(n)
    except FactorialArgumentError as e:
        print("function except positive argument instead got " + str(e.get_arg()))
    else:
        for i in range(n,0,-1):
            fact *= i
        return fact
def runtime_error():
    num1 = input("enter the first number: ")
    num2 = input("enter the second number: ")
    #we can check the input, just like that: if(num2==0): print("cant divide by zero")
    try:
        print("your division result is: ", int(num1)/int(num2))
    except ValueError:
        print("you put a string, i said enter a number")
    except ZeroDivisionError as e:
        print("you cant divide by zero:(")
        print("the error: ", e)
    #the else code will run if no exception was cath
    else:
        print("the code succeed!")
    #the finally code will run anyway, either if error was catch and not
    finally:
        print("this code is anyway running!")
def main():
    throw_err_example("noder")

if __name__ == "__main__":
    main()