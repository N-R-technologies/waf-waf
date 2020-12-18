docker run --rm -d -p 7777:80 vulnerables/web-dvwa #run the docker contain for the website
firefox http://localhost:7891/login.php & #run the firefox browser in the address of the docker container
mitmproxy -p 7891 -m reverse:http://localhost:7777 -s proxy.py # run the mimtproxy in reverse mode on localhost port 7777
