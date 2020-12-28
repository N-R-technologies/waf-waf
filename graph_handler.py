import numpy as np
import matplotlib.pyplot as plt
from risk_level import RiskLevel


class GraphHandler:
    plt.rcdefaults()
    risks_found = [0] * len(RiskLevel)

    @staticmethod
    def set_graph(attack_risks_findings):
        """
        This function will add the current attack risks findings values to the
        total detective's risks findings
        :param attack_risks_findings: the risk levels of the identified attack
        :type attack_risks_findings: list
        """
        for risk_found_day, risk_found_request in GraphHandler.risks_found[1:], attack_risks_findings[1:]:
            risk_found_day += risk_found_request

    @staticmethod
    def create_graph():
        """
        This function will create an image graph based on the detectors findings
        """
        objects = tuple([risk_level for risk_level in RiskLevel])
        y_pos = np.arange(len(objects))
        plt.bar(y_pos, GraphHandler.risks_found, align='center', alpha=0.5)
        plt.xticks(y_pos, objects)
        plt.locator_params(axis="y", nbins=max(objects) * 2)
        plt.ylabel('Risks Found')
        plt.xlabel('Risks Levels')
        plt.title('Risks Found In The Last Day')
        plt.savefig('risks_graph.png')

    @staticmethod
    def reset_findings():
        """
        function reset the findings of the detection for the graph
        """
        GraphHandler.risks_found = [0] * len(RiskLevel)
