docker run --rm -d -p 1234:8000 appsecco/dsvw #run the docker contain for apseco website
firefox http://localhost:4567/ & #run the firefox browser in the address of the docker container
mitmproxy -p 4567 -m reverse:http://localhost:1234 -s proxy.py # run the mimtproxy in reverse mode on localhost port 7777
