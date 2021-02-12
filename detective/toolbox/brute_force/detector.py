import time
import threading
import sched
import toml


class BruteForceDetector:

    DEFAULT_TIME = 10000

    def __init__(self):
        self._config_file_path = "brute_force_config.toml"
        self._schedule_threads()
        self._blocked_users = list()
        self._users_logins_attempts = dict()
        self._users_requests_counter = dict()
        self._users_delay = dict()
        self._blocked_users_lock = threading.Lock()
        self._logins_counter_lock = threading.Lock()
        self._requests_counter_lock = threading.Lock()
        self._users_delay_lock = threading.Lock()

    def _load_config(self, config_name):
        return toml.load(self._config_file_path).get(config_name, self.DEFAULT_TIME)

    def _schedule_threads(self):
        login_brute_force_scheduler = threading.Thread(target=self._start_function_scheduler, args=(self._check_brute_force_login, "check_login_brute_force_timer"))
        brute_force_scheduler = threading.Thread(target=self._start_function_scheduler, args=(self._check_brute_force, "check_brute_force_timer"))
        reset_blocked_users_scheduler = threading.Thread(target=self._start_function_scheduler, args=(self._reset_block_users, "reset_blocked_users_timer"))
        reset_users_delay_scheduler = threading.Thread(target=self._start_function_scheduler, args=(self._reset_users_delay, "reset_delay_ip_timer"))
        login_brute_force_scheduler.start()
        brute_force_scheduler.start()
        reset_blocked_users_scheduler.start()
        reset_users_delay_scheduler.start()

    def is_request_blocked(self, request, user_ip):
        login_url = toml.load(self._config_file_path).get("login_url", "")
        if login_url is not None and login_url in request.url:
            return user_ip in self._blocked_users
        return False

    def count_user_requests(self, request, user_ip_address):
        self._count_login_attempt(request, user_ip_address)
        self._count_request(user_ip_address)

    def add_delay(self, response, user_ip_address):
        with self._users_delay_lock:
            if user_ip_address in self._users_delay.keys():
                if self._users_delay[user_ip_address]:
                    response.headers["Retry-After"] = self._load_config("delay_time")
                    self._users_delay[user_ip_address] = False
                else:
                    self._users_delay[user_ip_address] = True

    def _count_login_attempt(self, request, user_ip_address):
        login_url = toml.load(self._config_file_path).get("login_url", "")
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
            scheduler.enter(self._load_config(time_until_start_field), 1, function)
            scheduler.run()

    def _check_brute_force_login(self):
        with self._logins_counter_lock, self._blocked_users_lock:
            for user_ip, logins_amount in self._users_logins_attempts.items():
                if logins_amount >= self._load_config("max_logins_per_minute"):
                    self._blocked_users.append(user_ip)
            self._users_logins_attempts.clear()

    def _check_brute_force(self):
        with self._requests_counter_lock, self._users_delay_lock:
            for user_ip_address, requests_amount in self._users_requests_counter.items():
                if requests_amount >= self._load_config("max_requests_per_half_minute"):
                    self._users_delay[user_ip_address] = True
            self._users_requests_counter.clear()

    def _reset_block_users(self):
        with self._blocked_users_lock:
            self._blocked_users.clear()

    def _reset_users_delay(self):
        with self._users_delay_lock:
            self._users_delay.clear()
