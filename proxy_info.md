# Summary
This is a text file which include all the new things we know about the proxy.py file.
There are the addons class build in functions, that are using for modify or seeing the transportation
the proxy get into it, and options are the way for us to configure our proxy.
## How to run the proxy
To run the proxy from the project directory, run the following command in the terminal:<br>
`mitmproxy --set ssl_insecure -s proxy.py`
## How to use the proxy
* To navigate between packets in the flow menu, use your arrow keys.
* To see more information about the packet you navigated to, press `Enter`.
* To exit the navigated packet, press `Q`.
* To exit the proxy, press `Q` followed by `Y`, or press `Ctrl+C` followed by `Y`.
  (`Ctrl+C` can be used anytime, but `Q` can only be used in the flow menu).
* To run the django website just write: `python3 manage.py runserver_plus --cert-file certs/local.crt --key-file certs/local.key.pem --reloader-interval 2 0.0.0.0:8000`
* The website is located at the following link: https://local.company.dev:8000/
