# WAF WAF V1.1 Manual
<p align="center">
  <img src="https://github.com/N-R-technologies/WAF-WAF/blob/master/misc/logo.png" alt="WAF WAF logo">
</p>

# Getting started
## Installation
You are able to use WAF WAF on both, your local machine and [docker](https://docs.docker.com/).

### Local Machine
After downloading WAF WAF, you first need to run the following command to install requirements:
```bash
pip install -r requirements.txt
```
After running the command, you will be able to run WAF WAF.

### Docker
Use the following command to install WAF WAF from docker:
```bash
docker pull wafwafdetective/waf_waf:V1.1
```

## Usage
### Local Machine
Run the command `./run.sh`.<br>
`run.sh` is the file that starts WAF WAF.<br>
After running the command, you will be required to fill 2 fields.
1. Your site's URL.
1. The port **clients** will use to access the server. (You have to make sure the clients can only access this specific port!).

If your server is running on HTTP, you have to specify that, for example: `http://localhost:80`.<br>
On HTTPS, there is no need to do it, writing `localhost:80` should be enough.

You may fill the fields while running the command itself, for example:<br>
`./run.sh localhost:7777 7891`<br>
You can also use the `-h` or `--help` flags as given parameters for more information.

### Docker
On docker, you can run WAF WAF either, automatically or manually.<br>
If you downloaded the notifications extension, you need to run it on your local machine with the following command:
```bash
python3 notification_server.py
```

#### Automatic Run
```bash
docker run  -it --privileged=true --net host --volume /var/run/dbus:/var/run/dbus wafwafdetective/waf_waf:V1.1
```
After running the command, you will be required to fill the same fields mentioned above.

#### Manual Run
```bash
docker run -it --privileged=true --net host --volume /var/run/dbus:/var/run/dbus wafwafdetective/waf_waf:V1.1 bash
```
Navigate to the `waf_waf` directory and run the command `./run.sh`.<br>
Running `./run.sh` here is similar to running it on a local machine.

After running WAF WAF, your terminal will become its proxy flow menu.<br>
Here's how to interact with it:
- To navigate between requests in the flow menu, use your arrow keys.
- To see more information about the request you navigated to, press `Enter`.
- To exit the navigated request, press `Q`.
- To exit the proxy, press `Q` followed by `Y`, or press `Ctrl+C` followed by `Y`.<br>
  (`Ctrl+C` can be used anytime, but `Q` can only be used in the flow menu).
  
## Notifications
There are 7 types of notifications that might appear on your screen:
- `Attacker Blocked` - Appears each time WAF WAF blocks a client, specifying the blocked IP.
- `Client Complained` - Appears when someone complains about a wrong diagnosis (specifying the complainer IP), which you can see in the CLI.
- `Successful Email!` - Should appear once a day, when the daily log was sent successfully to every configured user.
- `Refuse Error!` - Appears when the daily log was sent, but some users didn't receive it (specifying them).
- `Authentication Error!` - Appears when WAF WAF couldn't authenticate Gmail. If that happens, contact us immediately.
- `Mass Refuse Error!` - Appears when every configured user couldn't receive the daily log.
- `Unexpected Error!` - Appears when an unexpected error has occurred while sending the daily log.

## WAF WAF CLI
You might want to configure WAF WAF before running it, using its interactive CLI. You may also use the CLI for the options listed below.<br>

### Local Machine
Simply run the CLI using:
```bash
python3 cli.py
```

### Docker
First, You have to run the command `xhost +`.<br>
If you are worried that access control is disabled, write `xhost -` as soon as you finish using the WAF WAF CLI.<br>
Then, search the running WAF WAF container name with the following command:
```bash
docker ps
```
After locating the container's name, execute the container with the command below:
```bash
docker exec -it <name> bash
```
Navigate to the `waf_waf` directory and run the command `python3 cli.py`.

You should be able to see the CLI's main menu on your terminal with the following options:
1. `Start the network scan` - Run a scan on the local network. Results will be printed to the screen and saved in a file.
1. `Manage your emails configuration file` - Choosing this option will lead you to a new menu with the following options:
   1. `Display all the emails` - Display all existing emails who will receive the daily log.
   1. `Add an email to the list` - Add a new email that will receive the daily log.
   1. `Remove an email from the list` - Remove an existing email.
   1. `Exit (or simply press Q)` - Exit the current menu.
1. `Modify your site's URL` - In order to improve and to be more precise in our Brute Force detection, we would like to have your site's **login** URL.
1. `See wrong diagnosis file` - Get a list of all the clients who complained that WAF WAF identified an incorrect attack attempt.
1. `Get specific IP attacks` - Display detected malicious requests a client sent to the server. (Useful when someone complains about wrong diagnosis).
1. `Get help and explanation about our tool` - Displays a summary about WAF WAF.
1. `Exit (or simply press Q)` - Exit the CLI.

# Contact
We would like to hear reviews about WAF WAF!<br>
You feel like something is missing?<br>
You want to do something with WAF WAF, but you don't know how?<br>
Contact us at [wafdetectivebot@gmail.com](mailto:wafdetectivebot@gmail.com).
