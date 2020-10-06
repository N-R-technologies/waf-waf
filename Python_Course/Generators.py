"""genrators are usefull way to save and use really heavy data. if we want, for example, print all prime numbers
between one up to million, we can save all the numbers in list, and then print it, but this may take hours
better way is to use generator. the genrator is just create new object everytime we need one and save only the last
object, so the others dont take memory at all
generators can also help us to seperate all the logic behind the scene, and to show in our main code,
only the important things, thats make our code more clear
generators, can work together (couple of generators), all will work for one task in many levels
generator functions, are make it more easy and simple to use generators. you can see example of it: get_fibo"""
def print_many_numbers():
    #thats how we create generator for 1000000 numbers without run out of memory
    generator = (i for i in range (1000000))
    for num in generator:
        print(num)
def get_n_first_num(n):
    generator = (i for i in range(1000000))
    for i in range(n):
        #in that way we can get only the next object in the generator
        print(generator.__next__())

def get_fibo():
    num0 = 0
    num1 = 1
    yield num0
    yield num1
    while True:
        yield num1 + num0
        temp = num1
        num1 = num1 + num0
        num0 = temp


def pars_string(parse_range):
    first_generator = (parse.split("-") for parse in parse_range.split(","))
    second_generator = (number for start, stop in first_generator for number in range(int(start), int(stop) + 1))
    return second_generator
def main():
    #print_many_numbers()
    #get_n_first_num(5)
    #print(list(pars_string("1-4,5-7,11-20")))
    fibo_gen = get_fibo()
    print(next(fibo_gen))
    print(next(fibo_gen))
    print(next(fibo_gen))


if __name__ == "__main__":
    main()