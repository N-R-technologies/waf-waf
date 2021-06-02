import os
import time
import toml
import threading
import sched
from mitmproxy import http


class BruteForceDetector:
    CONFIGURATION_FILE_PATH = "detective/toolbox/brute_force/brute_force_configuration.toml"
    DEFAULT_TIME = 10000

    _blocked_users = list()
    _users_logins_attempts = dict()
    _users_requests_counter = dict()
    _users_delay = dict()
    _blocked_users_lock = threading.Lock()
    _logins_counter_lock = threading.Lock()
    _requests_counter_lock = threading.Lock()
    _users_delay_lock = threading.Lock()

    def __init__(self):
        self._schedule_threads()

    def _load_configuration(self, config_name, default_value):
        if os.path.exists(self.CONFIGURATION_FILE_PATH):
            return toml.load(self.CONFIGURATION_FILE_PATH).get(config_name, default_value)
        return default_value

    def _schedule_threads(self):
        login_brute_force_scheduler = threading.Thread(target=self._start_function_scheduler, args=(self._check_brute_force_login, "check_login_brute_force_timer"), daemon=True)
        brute_force_scheduler = threading.Thread(target=self._start_function_scheduler, args=(self._check_brute_force, "check_brute_force_timer"), daemon=True)
        reset_blocked_users_scheduler = threading.Thread(target=self._start_function_scheduler, args=(self._reset_block_users, "reset_blocked_users_timer"), daemon=True)
        reset_users_delay_scheduler = threading.Thread(target=self._start_function_scheduler, args=(self._reset_users_delay, "reset_delay_ip_timer"), daemon=True)
        login_brute_force_scheduler.start()
        brute_force_scheduler.start()
        reset_blocked_users_scheduler.start()
        reset_users_delay_scheduler.start()

    def is_request_blocked(self, request, user_ip):
        login_url = self._load_configuration("login_url", None)
        if login_url is not None and login_url in request.url:
            return user_ip in self._blocked_users
        return False

    def count_user_requests(self, request, user_ip_address):
        self._count_login_attempt(request, user_ip_address)
        self._count_request(user_ip_address)

    def add_delay(self, response, user_ip_address):
        with self._users_delay_lock:
            if user_ip_address in self._users_delay.keys():
                if self._users_delay[user_ip_address] <= 2:
                    self._users_delay[user_ip_address] += 1
                else:
                    response = http.HTTPResponse.make(429, "", {"Retry-After": "3"})
                    self._users_delay[user_ip_address] = 0
        return response

    def _count_login_attempt(self, request, user_ip_address):
        login_url = self._load_configuration("login_url", None)
        if login_url is not None and login_url in request.url:
            with self._logins_counter_lock:
                if user_ip_address in self._users_logins_attempts.keys():
                    self._users_logins_attempts[user_ip_address] += 1
                else:
                    self._users_logins_attempts[user_ip_address] = 1

    def _count_request(self, user_ip_address):
        with self._requests_counter_lock:
            if user_ip_address in self._users_requests_counter.keys():
                self._users_requests_counter[user_ip_address] += 1
            else:
                self._users_requests_counter[user_ip_address] = 1

    def _start_function_scheduler(self, function, time_until_start_field):
        while True:
            scheduler = sched.scheduler(time.time, time.sleep)
            scheduler.enter(self._load_configuration(time_until_start_field, self.DEFAULT_TIME), 1, function)
            scheduler.run()

    def _check_brute_force_login(self):
        with self._logins_counter_lock, self._blocked_users_lock:
            for user_ip, logins_amount in self._users_logins_attempts.items():
                if logins_amount >= self._load_configuration("max_logins_per_minute", self.DEFAULT_TIME):
                    self._blocked_users.append(user_ip)
            self._users_logins_attempts.clear()

    def _check_brute_force(self):
        with self._requests_counter_lock, self._users_delay_lock:
            for user_ip_address, requests_amount in self._users_requests_counter.items():
                if requests_amount >= self._load_configuration("max_requests_per_half_minute", self.DEFAULT_TIME):
                    self._users_delay[user_ip_address] = True
            self._users_requests_counter.clear()

    def _reset_block_users(self):
        with self._blocked_users_lock:
            self._blocked_users.clear()

    def _reset_users_delay(self):
        with self._users_delay_lock:
            self._users_delay.clear()
