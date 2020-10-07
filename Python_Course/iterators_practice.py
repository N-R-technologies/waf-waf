from functools import  reduce
class IDIterator:
    """a class used to represent an id iterator"""
    def __init__(self, id_number):
        self._id_number = id_number
    def __iter__(self):
        """function return the id iterator
        :return: the id iterator
        :rtype: IDIterator class object"""
        return self
    def __next__(self):
        """function return the next valid id
        :return: the next valid id
        :rtype: int"""
        update = 1
        while self._id_number + update <= 999999999:
            if check_id_valid(self._id_number + update):
                self._id_number = self._id_number + update
                return self._id_number
            update += 1
        raise StopIteration #raise an StopIteration exception, if we get to the max id possible
def check_id_valid(id_number):
    """function get a number, and return if this number is valid id
    :param id_number: the number to check if its valid id
    :type id_number: int
    :return: True if its valid ID, False if its not
    :rtype: boolean"""
    id_number = str(id_number)
    if len(id_number) != 9:
        return False
    id_list = [int(id_number[x-1])*2 if x % 2 == 0 else int(id_number[x-1]) for x in range(1,10)]
    id_list = [int(str(id_list[x-1])[0]) + int(str(id_list[x-1])[1]) if id_list[x-1] > 9 else id_list[x-1] for x in range(1,10)]
    return reduce(lambda x,y: x+y, id_list) % 10 == 0
def main():
    id = int(input("Enter ID: "))
    user_choice = input("Generator or Iterator? (gen/it)? ")
    if user_choice == "it":
        id_iterator = IDIterator(id)
        for i in range(10):
            print(next(id_iterator))
    elif user_choice == "gen":
        id_generator = (next_legal_id for next_legal_id in range(id,999999999) if check_id_valid(next_legal_id))
        """get all the ID from the user id and above
        :param id: user id
        :type id: int
        :return: the next llegal id
        :rtype: int"""
        for i in range(10):
            print(next(id_generator))
if __name__ == "__main__":
    main()