from datetime import date
import numpy as np
import matplotlib.pyplot as plt
from risk_level import RiskLevel

GRAPH_FILE_PATH = "log_related/graphs/risks_graph_"
GRAPH_TITLE = "Risks Found In The Last Day"
GRAPH_Y_TITLE = "Risks Found"
GRAPH_X_TITLE = "Risk Levels"
GREEN_IMPACT = 0.2
YELLOW_IMPACT = 0.4
ORANGE_IMPACT = 0.6
RED_IMPACT = 0.8
GREEN = "#00FF00"
YELLOW = "#FFFF00"
ORANGE = "#FF6400"
RED = "#FF0000"
BLANK = "#FFFFFF"


class GraphHandler:
    plt.rcdefaults()

    @staticmethod
    def create_graph(risks_found_today):
        """
        This function will create an image graph based on the detectors findings
        :param risks_found_today: all the risk levels which were found today
        :type risks_found_today: list
        """
        objects = tuple([risk_level for risk_level in range(len(RiskLevel))])
        y_pos = np.arange(len(objects))
        graph_colors = GraphHandler._calculate_risk_colors(risks_found_today)
        y_limit = 5
        if y_limit < max(risks_found_today[RiskLevel.Negligble:]) < 10:
            y_limit = 10
        elif max(risks_found_today[RiskLevel.Negligble:]) > 10:
            y_limit = max(risks_found_today[RiskLevel.Negligble:])
        plt.ylim([0, y_limit])
        plt.locator_params(axis='y', nbins=y_limit)
        plt.xticks(y_pos, objects)
        plt.xlabel(GRAPH_X_TITLE)
        plt.ylabel(GRAPH_Y_TITLE)
        plt.title(GRAPH_TITLE)
        plt.bar(y_pos, risks_found_today, align="center", alpha=1, color=graph_colors)
        plt.savefig(GRAPH_FILE_PATH + date.today().strftime("%d/%m/%Y").replace('/', '_') + ".png")

    @staticmethod
    def _calculate_risk_colors(risks_found_today):
        """
        This function will calculate the color the graph
        will show for each risk level according to its impact
        :param risks_found_today: all the risk levels which were found today
        :type risks_found_today: list
        :return: each of risk levels colors
        :rtype: list
        """
        graph_colors = [BLANK]
        amount_of_risks = len(RiskLevel) - 1
        for risk_occurrences, i in zip(risks_found_today[RiskLevel.Negligble:RiskLevel.Critical],
                                       range(RiskLevel.Negligble, RiskLevel.Critical)):
            multiplying_factor = i / amount_of_risks
            current_impact_level = round(multiplying_factor * risk_occurrences, 2)
            if GREEN_IMPACT <= current_impact_level < YELLOW_IMPACT:
                graph_colors.append(GREEN)
            elif YELLOW_IMPACT <= current_impact_level <= ORANGE_IMPACT:
                graph_colors.append(YELLOW)
            elif ORANGE_IMPACT < current_impact_level <= RED_IMPACT:
                graph_colors.append(ORANGE)
            elif RED_IMPACT < current_impact_level:
                graph_colors.append(RED)
            else:
                graph_colors.append(BLANK)
        graph_colors.append(RED if risks_found_today[RiskLevel.Critical] > 0 else BLANK)
        graph_colors.append(RED if risks_found_today[RiskLevel.Catastrophic] > 0 else BLANK)
        return graph_colors
