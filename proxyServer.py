import socket
import signal
import threading
class MyProxy:
    def __init__(self, config):
        # Create a TCP socket
        self.serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Shutdown on Ctrl+C
        signal.signal(signal.SIGINT, self.shutdown)



        # Re-use the socket
        self.serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # bind the socket to a public host, and a port
        self.serverSocket.bind((config['HOST_NAME'], config['BIND_PORT']))

        self.serverSocket.listen(50)  # become a server socket
        self.__clients = {}
        while True:
            # Establish the connection
            (clientSocket, client_address) = self.serverSocket.accept()
            print("client accepted")
            d = threading.Thread(target=self.proxy_thread, args=(clientSocket, client_address))
            d.setDaemon(True)
            d.start()
    def shutdown(self, signum, stack):
        self.serverSocket.close()
    def proxy_thread(self, clientSocket, client_address):
        # get the request from browser
        request = clientSocket.recv(1024).decode()
        print(request)
        # parse the first line
        first_line = request.split('\n')[0]

        # get url
        url = first_line.split(' ')[1]

        http_pos = url.find("://")  # find pos of ://
        if http_pos == -1:
            temp = url
        else:
            temp = url[(http_pos + 3):]  # get the rest of url

        port_pos = temp.find(":")  # find the port pos (if any)

        # find end of web server
        webserver_pos = temp.find("/")
        if webserver_pos == -1:
            webserver_pos = len(temp)

        webserver = ""
        port = -1
        if port_pos == -1 or webserver_pos < port_pos:

            # default port
            port = 80
            webserver = temp[:webserver_pos]

        else:  # specific port
            port = int((temp[(port_pos + 1):])[:webserver_pos - port_pos - 1])
            webserver = temp[:port_pos]

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((webserver, port))
        s.sendall(request.encode())
        print("connect to server")
        while True:
            try:
                print("get data from server")
                serverData = s.recv(1024)

                if len(serverData) > 0:
                    print("server send:")
                    print(serverData)
                    clientSocket.send(serverData)  # send to client
                else:
                    break

            except:
                s.close()
                clientSocket.close()
                break


def main():
    config = {}
    config['HOST_NAME'] = 'localhost'
    config['BIND_PORT'] = 12345
    poopoo = MyProxy(config)

if __name__ == "__main__":
    main()
