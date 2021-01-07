# Proxy Summary
The proxy have an addons class with built in functions that are using for modifying or seeing the transportation.<br>
The proxy is being set in the middle of the transportation and it is configured with the options class.

## How to run the Proxy
To run the proxy from the project directory, run the following command in the terminal:<br>
`mitmproxy --set ssl_insecure -s proxy_file.py`
- `--set ssl_insecure`: Enables the proxy to run with ssl requests.
- `-s proxy_file.py`: Loads the `proxy_file.py` file to mitmproxy.

## How to use the Proxy
There are some things you should know before running the proxy.
- To navigate between packets in the flow menu, use your arrow keys.
- To see more information about the packet you navigated to, press `Enter`.
- To exit the navigated packet, press `Q`.
- To exit the proxy, press `Q` followed by `Y`, or press `Ctrl+C` followed by `Y`.<br>
  (`Ctrl+C` can be used anytime, but `Q` can only be used in the flow menu).

# Docker Summary
A docker file is like a little virtual machine on your computer.<br>
The docker runs the image file of the machine.<br>
You can run multiple dockers at once.

# How to run the Docker
In order to run a docker you can use the following command:<br>
`docker run --rm -d -p computer_listen_port :containter_listen_port my_docker`
- `-rm`: If there is a docker with the same name currently running, remove it.
- `-d`: A flag that means to detach the docker.
- `-p computer_listen_port :containter_listen_port`: The address you want the docker to run on.
- `my_docker`: The name of the docker.
- If you want to see the packages the docker receives, you can add `--it`.

## How to run our Proxy with our Docker
To run the proxy with the website that runs on the docker from the project directory, run the following command in the terminal:<br>
`./run.sh`
