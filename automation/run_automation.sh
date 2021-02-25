apt install firefox
wget https://github.com/mozilla/geckodriver/releases/download/v0.24.0/geckodriver-v0.24.0-linux64.tar.gz
tar -xvzf geckodriver-v0.24.0-linux64.tar.gz
chmod +x geckodriveri
docker pull vulnerables/web-dvwa
docker run --rm -d -p 7777:80 vulnerables/web-dvwa
python /automation/automation.py no_waf_waf
docker rm -f $( docker ps -a -q)
docker run --rm -d -p 7777:80 vulnerables/web-dvwa
python /automation/automation.py waf_waf
docker rm -f $( docker ps -a -q)
