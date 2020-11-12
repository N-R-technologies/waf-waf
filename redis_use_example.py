# here is a quick and simple example of using the redis data base
# redis is an server data base, that inserting and getting values from him in o(1)
# very quick. the installation package will get all the values into the data base, and then
# the program only get out the values from the data base.

import redis
import subprocess
import atexit
import threading
import os
import time


def run_redis_server():
    """ This function will run the redis server """
    command = '~/Downloads/redis-6.0.9/src/redis-server'
    # need to change the line above, so it won't contain an absolute file path
    subprocess.run(command, shell=True, stdout=subprocess.PIPE, text=True)


def exit_handler(redis_object):
    """ This function will shutdown the redis server at program exit """
    print("\nClosing the redis server...")
    redis_object.shutdown()
    print("Redis server closed successfully")


def main():
    if os.path.isfile("dump.rdb"):  # dump.rdb is a useless automatically generated file we don't need now
        os.remove("dump.rdb")
    redis_object = redis.Redis()
    atexit.register(exit_handler, redis_object)
    # checking if the redis server is already running
    try:
        redis_object.ping()
        print("The server is already running\n")
    except redis.exceptions.ConnectionError:
        print("The server is not currently running\nStarting it...")
        threading.Thread(target=run_redis_server).start()
        time.sleep(0.05)  # need to wait for the program to run the redis server
        print("The server is now running!\n")

    redis_object.set('name', 'my waf project')
    print(redis_object.get('name').decode())  # decoding the data because it's received as binary
    redis_object.delete('name')
    try:
        input("Press {Ctrl + C} to close the redis server\n")
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
