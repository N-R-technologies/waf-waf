class GreetingCard:
    def __init__(self, sender="me", recipient="you"):
        self._recipient = recipient
        self._sender = sender
    def greeting_msg(self):
        return ("greet from ", self._sender, " sending to ", self._recipient)

