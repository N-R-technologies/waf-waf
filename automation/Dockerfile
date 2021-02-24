FROM python:3
ADD simple_automation.py /
RUN pip install selenium
RUN sudo apt install firefox
RUN wget https://github.com/mozilla/geckodriver/releases/download/v0.24.0/geckodriver-v0.24.0-linux64.tar.gz
RUN tar -xvzf geckodriver-v0.24.0-linux64.tar.gz
RUN chmod +x geckodriver
CMD [ "python", "./simple_automation.py" ]
