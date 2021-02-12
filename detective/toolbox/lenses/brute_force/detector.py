import os
import time
import threading
import sched
import toml


class BruteForceDetector:
    LOGIN_URL_FILE_PATH = "login_url.toml"
    DELAY_TIME = 3
    MAX_LOGINS_PER_MINUTE = 15
    MAX_REQUESTS_PER_HALF_MINUTE = 20
    CHECK_BRUTE_FORCE_TIMER = 30
    CHECK_LOGIN_BRUTE_FORCE_TIMER = 60
    RESET_BLOCKED_USERS_TIMER = 7200
    RESET_DELAY_IP_TIMER = 3600

    COMMON_LOGIN_URL = ("login", "signin")
    COMMON_LOGIN_FIELDS = {"uname", "username", "pass", "password",
                           "email", "mail", "user", "access", "identity",
                           "credential", "user account", "access code",
                           "login name", "name"}
    COMMON_USERNAME_FIELDS = ("uname", "username", "user", "access",
                              "identity", "credential", "user account",
                              "access code", "login name", "name")

    _login_url = ""
    _blocked_users = list()
    _users_logins_attempts = dict()
    _users_requests_counter = dict()
    _users_delay = dict()
    _blocked_users_lock = threading.Lock()
    _logins_counter_lock = threading.Lock()
    _requests_counter_lock = threading.Lock()
    _users_delay_lock = threading.Lock()

    def __init__(self):
        self._load_login_url_configuration(self.LOGIN_URL_FILE_PATH)
        self._schedule_threads()

    def _load_login_url_configuration(self, login_url_file_path):
        if os.path.exists(login_url_file_path):
            self._login_url = toml.load(login_url_file_path).get("url", None)

    def _schedule_threads(self):
        login_brute_force_scheduler = threading.Thread(target=self._login_brute_force_scheduler)
        brute_force_scheduler = threading.Thread(target=self._brute_force_scheduler)
        reset_blocked_users_scheduler = threading.Thread(target=self._reset_blocked_users_scheduler)
        reset_users_delay_scheduler = threading.Thread(target=self._reset_users_delay_scheduler)
        login_brute_force_scheduler.start()
        brute_force_scheduler.start()
        reset_blocked_users_scheduler.start()
        reset_users_delay_scheduler.start()

    def is_request_blocked(self, request):
        if self._is_login_request(request):
            username = self._get_username(request)
            return username in self._blocked_users
        return False

    def count_user_requests(self, request, user_ip_address):
        self._count_login_attempt(request)
        self._count_request(user_ip_address)

    def add_delay(self, response, user_ip_address):
        with self._users_delay_lock:
            if user_ip_address in self._users_delay.keys():
                if self._users_delay[user_ip_address]:
                    response.headers["Retry-After"] = self.DELAY_TIME
                    self._users_delay[user_ip_address] = False
                else:
                    self._users_delay[user_ip_address] = True

    def _count_login_attempt(self, request):
        if self._is_login_request(request):
            username = self._get_username(request.urlencoded_form)
            if username is not None:
                with self._logins_counter_lock:
                    if username in self._users_logins_attempts.keys():
                        self._users_logins_attempts[username] += 1
                    else:
                        self._users_logins_attempts[username] = 1

    def _count_request(self, user_ip_address):
        with self._requests_counter_lock:
            if user_ip_address in self._users_requests_counter.keys():
                self._users_requests_counter[user_ip_address] += 1
            else:
                self._users_requests_counter[user_ip_address] = 1

    def _is_login_request(self, request):
        login_fields_found = False
        if request.method == "POST":
            keys_set = set(request.urlencoded_form.keys())
            login_fields_found = self.COMMON_LOGIN_FIELDS & keys_set and any(map(request.url.__contains__, self.COMMON_LOGIN_FIELDS))
        return self._login_url in request.url or login_fields_found

    def _get_username(self, login_request):
        request_fields = login_request.keys()
        for username_field in self.COMMON_USERNAME_FIELDS:
            if username_field in request_fields:
                return login_request[username_field]
        return None

    def _login_brute_force_scheduler(self):
        while True:
            scheduler = sched.scheduler(time.time, time.sleep)
            scheduler.enter(self.CHECK_LOGIN_BRUTE_FORCE_TIMER, 1, self._check_brute_force_login)
            scheduler.run()

    def _brute_force_scheduler(self):
        while True:
            scheduler = sched.scheduler(time.time, time.sleep)
            scheduler.enter(self.CHECK_BRUTE_FORCE_TIMER, 1, self._check_brute_force)
            scheduler.run()

    def _reset_blocked_users_scheduler(self):
        while True:
            scheduler = sched.scheduler(time.time, time.sleep)
            scheduler.enter(self.RESET_BLOCKED_USERS_TIMER, 1, self._reset_block_users)
            scheduler.run()

    def _reset_users_delay_scheduler(self):
        while True:
            scheduler = sched.scheduler(time.time, time.sleep)
            scheduler.enter(self.RESET_DELAY_IP_TIMER, 1, self._reset_users_delay)
            scheduler.run()

    def _check_brute_force_login(self):
        with self._logins_counter_lock, self._blocked_users_lock:
            for username, logins_amount in self._users_logins_attempts.items():
                if logins_amount >= self.MAX_LOGINS_PER_MINUTE:
                    self._blocked_users.append(username)
            self._users_logins_attempts.clear()

    def _check_brute_force(self):
        with self._requests_counter_lock, self._users_delay_lock:
            for user_ip_address, requests_amount in self._users_requests_counter.items():
                if requests_amount >= self.MAX_REQUESTS_PER_HALF_MINUTE:
                    self._users_delay[user_ip_address] = True
            self._users_requests_counter.clear()

    def _reset_block_users(self):
        with self._blocked_users_lock:
            self._blocked_users.clear()

    def _reset_users_delay(self):
        with self._users_delay_lock:
            self._users_delay.clear()
