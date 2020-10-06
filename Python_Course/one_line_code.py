import functools
"""def multiply(num1, num2):
    return num1*num2"""
def is_big(num1,num2):
    return num2 if num2 > num1 else num1
def is_prime(num):
    for i in range(num-1, 1, -1):
        if num % i == 0:
            return False
    return True
"""map function does iterate all items from both list, and pass them as params
to the callback function in this case: multiply. the meaning of that, is that now we will have
a new list, that every item, will be the multiply result of two nums from lists"""
def map_example(list1, list2):

   return list(map(lambda x,y:x*y, list1, list2))
"""filter function, get callback function and list of numbers, then return a new iterator contains the items that
pass the condition from the callback function, so if the function will return true for the
second item in the list, he will still be in the new list, but if it will return false,
the function will not return him"""
def filter_example(max_num):
    return list(filter(is_prime, range(max_num)))
"""reduce function, get the callback function, and list of items, then it run the callback on
every two items in list, until it get one item. for example, if the list is: [1,2,3,4]
and the callback function return the sum of two items, then the result will be 10"""
def reduce_example(max_num):
    return functools.reduce(is_big, filter_example(max_num))
"""lmbda function is just one line function, that define in the way:
key word: lmbda *parameters*: *return value*
lambda function can contain in dictionary of function for example:"""
def creating_oneline_list():
    list1 = [2,3,6]
    list2 = [5,1,8]
    square_list = [x**2 for x in range (100)]
    multiply_list = [x*y for x in list1 for y in list2]
    square_only_even = [x**2 for x in range(10) if x%2==0]
    square_two_conditions = [x**2 for x in range(10) if x>3 if x<7]
    even_odd_list = ["Even" if x%2==0 else "Odd" for x in range(10) ]
    list_of_multiply = [[i*2,i] for i in range(10) ]
def get_long_name():
    print(functools.reduce(lambda name1, name2: (name2 if len(name2) > len(name1) else name1),open("names.txt", "r").read().split("\n")))
def get_sum_of_lengths():
    print(functools.reduce(lambda len1, len2: len1 + len2,[len(x) for x in open("names.txt", "r").read().split("\n")]))

def get_shortest_names():
    lowest_length = [len(x) for x in open("names.txt", "r").read().split("\n")]
    lowest_length.sort()
    print("\n".join(list(filter(lambda name: len(name)==lowest_length[0], open("names.txt", "r").read().split("\n")))))
def create_lens_file():
    open("name_length.txt", "w").write("\n".join([str(len(x)) for x in open("names.txt", "r").read().split("\n")]))
def get_names_in_length():
    length = input("enter a length")
    print("\n".join(list(filter(lambda name: len(name)==int(length), open("names.txt", "r").read().split("\n")))))
def main():
    """function_dict = {1:lambda x,y:x+y, 2:lambda x,y: x-y, 3:lambda x,y:x*y,4:lambda x,y:x/y}
    x = int(input("enter the first number"))
    y = int(input("enter the second number"))
    print("result=")
    print(function_dict[int(input("enter the number of action you\n1-add\n2-minus\n3-multiply\n4-divide\n"))](x,y))
    print(map_example([2,3,7,-2], [1,3,8,-4]))
    print(filter_example(100))
    print(reduce_example(100))
    creating_oneline_list()"""
    get_names_in_length()


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()


# See PyCharm help at https://www.jetbrains.com/help/pycharm/
