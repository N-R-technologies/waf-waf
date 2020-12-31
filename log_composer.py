import os
from datetime import date
from fpdf import FPDF

LOG_FILE_PATH = "log_related/logs/daily_log_"
BACKGROUND_FILE_PATH = "log_related/images/background.jpg"
ICON_FILE_PATH = "log_related/images/icon.jpg"
CALIBRI_BOLD_FILE_PATH = "log_related/fonts/calibri_bold.ttf"
CALIBRI_LIGHT_FILE_PATH = "log_related/fonts/calibri_light.ttf"
LOG_TITLE = "WAF Daily Log"


class LogComposer:
    _daily_log = None

    def __init__(self):
        """
        This function will initialize the pdf log document and will set the title
        """
        self._daily_log = FPDF()
        self._daily_log.add_page()
        self._load_calibri(CALIBRI_BOLD_FILE_PATH, CALIBRI_LIGHT_FILE_PATH)
        self._set_log_header(LOG_TITLE)

    def _load_calibri(self, calibri_bold_file_path, calibri_light_file_path):
        self._remove_calibri_configuration(calibri_bold_file_path, calibri_light_file_path)
        if os.path.exists(calibri_bold_file_path) and os.path.exists(calibri_light_file_path):
            self._daily_log.add_font("Calibri", 'B', calibri_bold_file_path, uni=True)
            self._daily_log.add_font("Calibri Light", "", calibri_light_file_path, uni=True)
        else:
            raise FileNotFoundError

    def _remove_calibri_configuration(self, calibri_bold_file_path, calibri_light_file_path):
        calibri_bold_file_path = calibri_bold_file_path.replace(".ttf", ".pkl")
        calibri_light_file_path = calibri_light_file_path.replace(".ttf", ".pkl")
        if os.path.exists(calibri_bold_file_path):
            os.remove(calibri_bold_file_path)
        if os.path.exists(calibri_light_file_path):
            os.remove(calibri_light_file_path)

    def _set_log_header(self, title):
        """
        This function will write the the log's date, title and background
        :param title: the title of the page
        :type title: string
        """
        self._daily_log.image(BACKGROUND_FILE_PATH, x=0, y=0, w=200, h=300)
        self._daily_log.set_font("Calibri Light", size=12)
        self._daily_log.cell(w=190, h=5, txt=date.today().strftime("%d/%m/%Y"), ln=1, align='R')
        self._daily_log.set_font("Calibri", "BU", size=24)
        self._daily_log.cell(w=200, h=20, txt=title, ln=1, align='C')

    def write_to_log(self, info):
        """
        This function will write all the attacks information
        into the daily log file and will save it
        :param info: all the attacks information
        :type info: dict
        """
        for attack_name, attack_info in info.items():
            self._daily_log.add_page()
            self._set_log_header(attack_name)
            self._daily_log.set_font("Calibri Light", size=12)
            for detail in attack_info:
                self._daily_log.cell(w=200, h=10, txt=detail, ln=2, align='L')
            self._daily_log.image(ICON_FILE_PATH, x=80, w=70, h=80)
        self._daily_log.output(LOG_FILE_PATH + date.today().strftime("%d/%m/%Y").replace('/', '_') + ".pdf")
