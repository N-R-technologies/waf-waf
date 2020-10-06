import os
class accord:
    def __init__(self, frequence):
        self._frequence = frequence
    def get_frequence(self):
        return self._frequence
class MusicNotes:
    #create our own iterator with override next and iter functions
    def __init__(self):
        self._music_accord = []
        self._accord_index = -1
    def add_accord(self, accord):
        self._music_accord.append(accord)
    def get_len(self):
        return len(self._music_accord)
    def __iter__(self):
        return self
    def __next__(self):
        self._accord_index += 1
        if self._accord_index >= (len(self._music_accord)):
            raise StopIteration
        return self._music_accord[self._accord_index].get_frequence()

def create_print_accords():
    MN = MusicNotes()
    frequences = [55, 61.74, 65.41,73.42,82.41,87.31,98]
    i = 1
    while i <= 16:
        for j in range(len(frequences)):
            MN.add_accord(accord(frequences[j]*i))
        i = i *2
    for freq in MN:
        print(freq)


def print_numbers_divided_by(divided):
    numbers = iter(list(range(1, 101)))
    while True:
        try:
            for i in range(divided-1):
                next(numbers)
            print(next(numbers))
        except:
            break
def play_yonatan_the_small():
    freqs = {"la": 220,
             "si": 247,
             "do": 261,
             "re": 293,
             "mi": 329,
             "fa": 349,
             "sol": 392,
             }
    notes = "sol,0.25-mi,0.25-mi,0.5-fa,0.25-re,0.25-re,0.5-do,0.25-re,0.25-mi,0.25-fa,0.25-sol,0.25-sol,0.25-sol,0.5"
    lyrics = [note.split(",") for note in notes.split("-")]
    accord = iter(lyrics)
    #this is how for loop look in the backend. accord is an iterator (pointer too the lyrics list of lists)
    #when we want to get iterator for list or something like that, we jsut need to use iter function
    #evry iterate we want to go to the next accord we just use the next function.
    while True:
        try:
            curr_cord = next(accord)
            os.system('play -nq -t alsa synth {} sine {}'.format(float(curr_cord[1]), freqs[curr_cord[0]]))
        except:
            break

def main():
    #play_yonatan_the_small()
    #print_numbers_divided_by(20)
    create_print_accords()
if __name__ == "__main__":
    main()
