docker run --rm -d -p 7777:80 vulnerables/web-dvwa
firefox http://localhost:7891/login.php &
mitmproxy -p 7891 -m reverse:http://localhost:7777 -s proxy.py
