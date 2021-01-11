import re
from detective.toolbox.risk_levels import RiskLevels


class BasicChecks:
    @staticmethod
    def cookie_steal(request):
        """
        This function will check if the user tries to
        inject users cookies stealing
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.CATASTROPHIC if re.search(r"""\bdocument\.cookie\b""", request) else RiskLevels.NO_RISK

    @staticmethod
    def script(request):
        """
        This function will check if the user tries to
        inject any kind of script as input
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.CATASTROPHIC if re.search(r"""<\s*script/*(?:\s+.+?>|\s*>.+?)(?:<\s*/\s*script\s*>)?""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def tag_attributes(request):
        """
        This function will check if the user tries to
        inject a script via attributes of different tags
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.CRITICAL \
            if re.search(r"""<\s*(?:img|body|a|svg)(?:/|\s+).+?=\s*(?:(?:\"|'|`)\s*)?(?:javascript\s*:\s*)?\balert\b""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def img_input_src(request):
        """
        This function will check if the user tries to
        inject a script via the img or input tag's src attributes
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.CRITICAL \
            if re.search(r"""<\s*(?:img|input).+?(?:src|dnysrc|lowsrc)\s*=\s*(?:(?:\"|'|`)\s*)?javascript\s*:\s*alert""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def old_img_src(request):
        """
        This function will check if the user tries to
        inject a script via the old img tag's src attributes
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.MODERATE \
            if re.search(r"""<\s*img.+?(?:src|dnysrc|lowsrc)\s*=\s*(?:(?:\"|'|`)\s*)?(?:vbscript\s*:\s*msgbox|livescript\s*:\s*\[)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def list_style_image(request):
        """
        This function will check if the user tries to
        inject a script via the style tag's list-style-image attribute
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.MODERATE \
            if re.search(r"""<\s*style.+?{\s*list-style-image\s*:\s*.+?\(\s*(?:(?:\"|'|`)\s*)?javascript\s*:\s*alert""", request) \
            else RiskLevels.NO_RISK
