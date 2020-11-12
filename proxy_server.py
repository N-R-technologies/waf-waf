import socket
import signal
import threading


class MyProxy:
    def __init__(self, config):
        """ This function will create and run the proxy server """
        print("Starting the proxy...")
        # Create a TCP socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Shutdown on Ctrl+C
        signal.signal(signal.SIGINT, self.shutdown)

        # Re-use the socket
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # bind the socket to a public host, and a port
        self.server_socket.bind((config['HOST_NAME'], config['BIND_PORT']))

        self.server_socket.listen(50)  # become a server socket
        self.__clients = dict()

        print("Done!\n")
        print("Waiting for clients connection...")
        while True:
            try:
                # Establish the connection
                (client_socket, client_address) = self.server_socket.accept()
                print("Client accepted!")
                d = threading.Thread(target=self.proxy_thread, args=(client_socket, client_address))
                d.setDaemon(True)
                d.start()
            except Exception:
                break

    def shutdown(self, signum, stack):
        """ This function will close the proxy server """
        print("\nClosing the proxy...")
        self.server_socket.close()
        print("Done!")

    def proxy_thread(self, client_socket, client_address):
        """ This function will handle clients """
        # get the request from browser
        request = client_socket.recv(1024).decode()
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

        else:
            # specific port
            port = int((temp[(port_pos + 1):])[:webserver_pos - port_pos - 1])
            webserver = temp[:port_pos]

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((webserver, port))
        s.sendall(request.encode())

        while True:
            try:
                server_data = s.recv(1024)

                if len(server_data) > 0:
                    print(server_data)
                    client_socket.send(server_data)  # send to client
                else:
                    break

            except Exception:
                s.close()
                client_socket.close()
                break


def main():
    config = dict()
    config['HOST_NAME'] = 'localhost'
    config['BIND_PORT'] = 12345
    MyProxy(config)


if __name__ == "__main__":
    main()
