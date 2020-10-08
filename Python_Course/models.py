import my_model
import pyttsx3
class BirthdayCard(my_model.GreetingCard):
    def __init__(self, sender="me", recipient="you", sender_age=18):
        super().__init__(sender, recipient)
        self._sender_age = sender_age
    def greeting_msg(self):
        return super().greeting_msg() + (" Happy ", self._sender_age, " Birthday!")
def main():
    BC = BirthdayCard("noam", "ron", 17)
    print(BC.greeting_msg())
    engine = pyttsx3.init()
    engine.say(BC.greeting_msg())
    engine.runAndWait()
if __name__ == "__main__":
    main()