FROM python:3
RUN pip install selenium
ADD automation.py /
ADD geckodriver /
ADD run_automation.sh /
RUN chmod +x run_automation.sh
