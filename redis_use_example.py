"""here is a quick and simple example of using the redis data base
redis is an server data base, that inserting and getting values from him in o(1)
very quick. the installation package will get all the values into the data base, and then
the program only get out the values from the data base. """
import subprocess
import atexit
import redis
import threading


def run_redis_server():
    """function run the redis server"""
    command = '~/Downloads/redis-6.0.9/src/redis-server'
    subprocess.run(command, shell=True, stdout=subprocess.PIPE, text=True)


def exit_handler(redis_object):
    """
    This will shutdown the redis server
    """
    print("closing the redis server")
    redis_object.shutdown()


def main():
    threading.Thread(target=run_redis_server).start()
    redis_object = redis.Redis()
    atexit.register(exit_handler, redis_object)
    redis_object.set('name', 'my waf project')
    print(redis_object.get('name').decode())  # get data in binary
    redis_object.delete('name')


if __name__ == "__main__":
    main()
