FROM python:3
ADD simple_automation.py /
RUN pip install selenium
RUN sudo apt install firefox
CMD [ "python", "./simple_automation.py" ]
