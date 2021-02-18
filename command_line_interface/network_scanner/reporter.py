import os
from datetime import datetime
from .data.vulnerabilities_info import info
from misc import Colors


class Reporter:
    LOG_FILE_PATH = "network_scanner/data/logs/scan_log_"
    IS_FOUND = 0
    PRINT_COLOR = 1

    def report_conclusions(self, results):
        """
        This function will print the conclusions of the last network scan
        :param results: the results of the scan
        :type results: dict
        """
        print(f"\n{Colors.GREEN}*****************************Scan Conclusions*****************************\n")
        for potential_risk_name, potential_risk_detected in results.items():
            if potential_risk_detected[self.IS_FOUND]:
                print(potential_risk_detected[self.PRINT_COLOR] + info[potential_risk_name])
        print(Colors.BLUE)
        self._report_log(results)

    def _report_log(self, results):
        """
        This function will write the conclusions of
        the last network scan into a log
        :param results: the results of the scan
        :type results: dict
        """
        scan_file_path = self.LOG_FILE_PATH + datetime.now().strftime("%d_%m_%Y__%H_%M_%S") + ".txt"
        with open(scan_file_path, 'w') as scan_log:
            scan_log.write("*****************************Scan Conclusions*****************************\n\n")
            for potential_risk_name, potential_risk_detected in results.items():
                if potential_risk_detected[self.IS_FOUND]:
                    scan_log.write(info[potential_risk_name] + '\n')
            scan_log.close()
        print(f"The report has also been saved at:\n{os.path.abspath(scan_file_path)}")
