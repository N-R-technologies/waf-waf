import re
from detective.toolbox import RiskLevels


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
    def alert(request):
        """
        This function will check if the user tries to inject an alert function
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.MODERATE if re.search(r"""\balert\b\s*(?:>\s*)?\([^\)]+?\)""", request) else RiskLevels.NO_RISK

    @staticmethod
    def eval(request):
        """
        This function will check if the user tries to inject an eval function
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"""\beval\b\s*\([^\)]+?\)""", request) else RiskLevels.NO_RISK

    @staticmethod
    def utf7(request):
        """
        This function will check if the user tries to
        inject a script encoded with UTF-7
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.MODERATE if re.search(r"""\bcharset\b\s*=\s*utf-7""", request) else RiskLevels.NO_RISK

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
        return RiskLevels.CATASTROPHIC if re.search(r"""<\s*script(?:/|\s|\()(?:.+?>|>.+?)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def script_access(request):
        """
        This function will check if the user tries to allow himself
        script access via the embed tag's allowscriptaccess attribute
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.CRITICAL \
            if re.search(r"""<\s*embed(?:/|\s).*?allowscriptaccess\s*=(?:(?:\"|'|`)\s*)?always""", request) else RiskLevels.NO_RISK

    @staticmethod
    def tag_attributes(request):
        """
        This function will check if the user tries to
        use any attributes of different tags
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"""<\s*(?:img|body|i?frame|a|svg|isindex)(?:/|\s).+?=""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def img_src(request):
        """
        This function will check if the user tries to
        inject a script via the img or input tag's src attributes
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.MODERATE if re.search(r"""<\s*img(?:/|\s).*?(?:src|dnysrc|lowsrc)\s*=""", request) else RiskLevels.NO_RISK

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
            if re.search(r"""<\s*img(?:/|\s).*?(?:src|dnysrc|lowsrc)\s*=\s*(?:(?:\"|'|`)\s*)?(?:vbscript\s*:\s*msgbox|livescript\s*:\s*\[)""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def tags_src(request):
        """
        This function will check if the user tries to
        inject a script via different tags src attribute
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.MODERATE if re.search(r"""<\s*(?:input|bgsound|xml)(?:/|\s).*?src\s*=""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def div_background(request):
        """
        This function will check if the user tries to
        inject a script via div tag's background attribute
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.MODERATE \
            if re.search(r"""<\s*div(?:/|\s).*?style\s*=\s*(?:(?:\"|'|`)\s*)?(?:background-image|width)\s*:""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def style_background(request):
        """
        This function will check if the user tries to
        inject a script via style tag's background attribute
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.MODERATE \
            if re.search(r"""<\s*style(?:/|\s)*>.*?{\s*(?:(?:\"|'|`)\s*)?background-image\s*:""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def tags_background(request):
        """
        This function will check if the user tries to
        inject a script via different tags background attribute
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.MODERATE if re.search(r"""<\s*(?:table|td)(?:/|\s).*?background\s*=""", request) else RiskLevels.NO_RISK

    @staticmethod
    def link_base_href(request):
        """
        This function will check if the user tries to
        inject a script via the link or base tags href attribute
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.MODERATE if re.search(r"""<\s*(?:link|base)(?:/|\s).*?href\s*=""", request) else RiskLevels.NO_RISK

    @staticmethod
    def br_size(request):
        """
        This function will check if the user tries to
        inject a script via the br tag's size attribute
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.MODERATE if re.search(r"""<\s*br(?:/|\s).*?size\s*=""", request) else RiskLevels.NO_RISK

    @staticmethod
    def meta_content(request):
        """
        This function will check if the user tries to
        inject a script via the meta tag's content attribute
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.MODERATE if re.search(r"""<\s*meta(?:/|\s).*?(?:content|url)\s*=""", request) else RiskLevels.NO_RISK

    @staticmethod
    def html_body_xml(request):
        """
        This function will check if the user tries to inject a
        script through xml via the html and body tags to attribute
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.MODERATE if re.search(r"""<\s*html(?:/|\s)*>\s*<\s*body(?:/|\s)*>.*?to\s*=""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def object_type(request):
        """
        This function will check if the user tries to
        inject a script via the object tag's type attribute
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.MODERATE \
            if re.search(r"""<\s*object(?:/|\s).*?type\s*=(?:(?:\"|'|`)\s*)?text\s*/\s*x-scriptlet""", request) else RiskLevels.NO_RISK

    @staticmethod
    def style_type(request):
        """
        This function will check if the user tries to
        inject a script via the style tag's type attribute
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.MODERATE \
            if re.search(r"""<\s*style(?:/|\s).*?type\s*=(?:(?:\"|'|`)\s*)?text\s*/\s*(?:javascript|css)""", request) else RiskLevels.NO_RISK

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
        return RiskLevels.MODERATE if re.search(r"""<\s*style(?:/|\s).*?{\s*list-style-image\s*:""", request) \
            else RiskLevels.NO_RISK

    @staticmethod
    def xss_style_comments(request):
        """
        This function will check if the user's request contains html comment
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.SLIGHT if re.search(r"""style\s*=\s*.*?(/\*.*?\*/)""", request) else RiskLevels.NO_RISK

    @staticmethod
    def xss_html_comments(request):
        """
        This function will check if the user's request contains html comment
        :param request: the user's request
        :type request: string
        :return: the dangerous level according to the findings
        :rtype: enum RiskLevels
        """
        return RiskLevels.NEGLIGIBLE if re.search(r"""<!--.*-->""", request) else RiskLevels.NO_RISK
