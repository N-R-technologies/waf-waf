category = "XSS"

general_info = "Cross-site scripting (also known as XSS) is a web security vulnerability that allows an\n" \
               " attacker to compromise the interactions that users have with a vulnerable application. \n" \
               "It allows an attacker to circumvent the same origin policy, which is designed to segregate \n" \
               "different websites from each other. Cross-site scripting vulnerabilities normally allow an \n" \
               "attacker to masquerade as a victim user, to carry out any actions that the user is able to\n" \
               " perform, and to access any of the user's data. If the victim user has privileged access \n" \
               "within the application, then the attacker might be able to gain full control over all of \n" \
               "the application's functionality and data.\n"

deep_info = {
    'cookie_steal': 'The attacker can inject and see some sensitive data\n'
                    'by printing or access the variable document.cookie\n',
    'alert': 'Commen javascript function, that is being used by xss attackers\n'
             'is the alert function, that pop up little notification\n',
    'eval': 'With the eval function attacker can execute external code on the\n' \
            'server side, this can be super dangerous because this code can harm the server\n',
    'utf7': 'With the UTF-7 encoding, potential attacker can hide his malicious code and attack\n'
            'The server, with out the parser or input checker even know about that\n',
    'script': 'By using the scrip tag, the attacker can inject and run some malicious script on the server\n'
              'this kind of tag is very common and used a lot by xss attackers\n',
    'script_access': 'If an attacker change the allow_access_script tag to True, he can inject the server\n'
                     'with a script tag, and force him to execute it\n',
    'tag_attributes': 'Tag attributes provide an attacker entry point to inejct and harm the server\n'
                      'by passing him malicious script hiding with png or svg format\n',
    'img_src': 'Attacker can use image tag in order to include malicious code\n',
    'old_img_src': 'Attacker can use image tag in order to include malicious code\n',
    'tags_src': 'Attacker can use tags like input or xml to include malicious code that will be stored\n'
                'on the server side, and user will run it\n',
    'div_background': 'Attacker can create new div in the website frontend, and set its\n'
                      'background image, to contain malicious code which will run when the frontend load on the client side\n',
    'style_background': 'Attacker can create new div in the website frontend, and set its\n'
                      'background image, to contain malicious code which will run when the frontend load on the client side\n',
    'tags_background': 'Attacker can create new div in the website frontend, and set its\n'
                      'background image, to contain malicious code which will run when the frontend load on the client side\n',
    'link_base_href': 'Attacker can include some links in his attack, to malicious files or websites\n',
    'br_size': 'the br size= element can come before the function, and disturb the parser\n',
    'meta_content': 'Meta content or url, is an option that the attacker include some malicious\n'
                    'content that users will harm when they access the server\n',
    'html_body_xml': 'With editing the html body of the frontend as he wish, a potential attacker\n'
                     'can harm the server, and the users\n',
    'object_type': 'Object type tag, is a way which an attacker can inject malicious script with xss into the server\n',
    'style_type': 'Style type tag, is a way which an attacker can inject malicious script with xss into the server\n',
    'list_style_image': 'Style type tag, is a way which an attacker can inject malicious script with xss into the server\n',
    'xss_style_comments': 'xss style comment, are not dangerous for themselves, but there are an indicator for\n'
                          'an attack try into the server\n',
    'xss_html_comments': 'html style comment, are not dangerous for themselves, but there are an indicator for\n'
                          'an attack try into the server\n',
    'blind_xss': 'With blind xss, the attacker can redirect or even inject the server some malicious code\n'
                 'that found in another url or ip address\n',
    'fscommand': 'fscommand attacker can use this when executed from within an embedded flash object\n',
    'onabort': 'onabort when user aborts the loading of an image\n',
    'onactivate': 'onactivate when object is set as the active element\n',
    'onafterprint': 'onafterprint activates after user prints or previews print job\n',
    'onafterupdate': 'onafterupdate activates on data object after updating data in the source object\n',
    'onbeforeactivate': 'onbeforeactivate fires before the object is set as the active element\n',
    'onbeforecopy': 'onbeforecopy attacker executes the attack string right before a selection is copied to the clipboard\n'
                 ' - attackers can do this with the execcommand("copy") function\n',
    'onbeforecut': 'onbeforecut attacker executes the attack string right before a selection is cut\n',
    'onbeforedeactivate': 'onbeforedeactivate fires right after the activeelement is changed from the current object\n',
    'onbeforeeditfocus': 'onbeforeeditfocus fires before an object contained in an editable element enters a\n'
                      'ui-activated state or when an editable container object is control selected\n',
    'onbeforepaste': 'onbeforepaste user needs to be tricked into pasting or be forced into it using the execcommand("paste")\n function\n',
    'onbeforeprint': 'onbeforeprint user would need to be tricked into printing or attacker could use the print()\n or execcommand("print") function)\n',
    'onbeforeunload': 'onbeforeunload user would need to be tricked into closing the browser - attacker cannot unload\n '
                   'windows unless it was spawned from the parent\n',
    'onbeforeupdate': 'onbeforeupdate activates on data object before updating data in the source object\n',
    'onbegin': 'onbegin the onbegin event fires immediately when the element’s timeline begins\n',
    'onblur': 'onblur in the case where another popup is loaded and window looses focus\n',
    'onbounce': 'onbounce fires when the behavior property of the marquee object is set to “alternate” and the\n '
             'contents of the marquee reach one side of the window\n', 'oncellchange': 'oncellchange fires when data changes in the data provider\n',
    'onchange': 'onchange select, text\n, or textarea field loses focus and its value has been modified\n',
    'onclick': 'onclick someone clicks on a form\n',
    'oncontextmenu': 'oncontextmenu user would need to right click on attack area\n',
    'oncontrolselect': 'oncontrolselect fires when the user is about to make a control selection of the object\n',
    'oncopy': 'oncopy user needs to copy something or it can be exploited using the execcommand("copy") command\n',
    'oncut': 'oncut user needs to copy something or it can be exploited using the execcommand("cut") command\n',
    'ondataavailable': 'ondataavailable user would need to change data in an element\n,'
                    ' or attacker could perform the same function\n',
    'ondatasetchanged': 'ondatasetchanged fires when the data set exposed by a data source object changes\n',
    'ondatasetcomplete': 'ondatasetcomplete fires to indicate that all data is available from the data source object\n',
    'ondblclick': 'ondblclick user double-clicks a form element or a link\n',
    'ondeactivate': 'ondeactivate fires when the activeelement is changed from the current object to another\n '
                 'object in the parent document\n', 'ondrag': 'ondrag requires that the user drags an object\n',
    'ondragend': 'ondragend requires that\n the user drags an object\n',
    'ondragleave': 'ondragleave requires that the user drags an object off a valid location\n',
    'ondragenter': 'ondragenter requires that the user drags an object into a valid location\n',
    'ondragover': 'ondragover requires that the user drags an object into a valid location\n',
    'ondragdrop': 'ondragdrop user drops an object (e.g. file) onto the browser window\n',
    'ondragstart': 'ondragstart occurs when user starts drag operation\n',
    'ondrop': 'ondrop user drops an object (e.g. file) onto the browser window\n',
    'onend': 'onend the onend event fires when the timeline ends\n',
    'onerror': 'onerror loading of a document or image causes an error\n',
    'onerrorupdate': 'onerrorupdate fires on a databound object when an error occurs while updating the associated \n'
                  'data in the data source object\n',
    'onfilterchange': 'onfilterchange fires when a visual filter completes state change\n',
    'onfinish': 'onfinish attacker can create the exploit when marquee is finished looping\n',
    'onfocus': 'onfocus attacker executes the attack string when the window gets focus\n',
    'onfocusin': 'onfocusin attacker executes the attack string when window gets focus\n',
    'onfocusout': 'onfocusout attacker executes the attack string when window looses focus\n',
    'onhashchange': 'onhashchange fires when the fragment identifier part of the document’s current address changed\n',
    'onhelp': 'onhelp attacker executes the attack string when users hits f1 while the window is in focus\n',
    'oninput': 'oninput the text content of an element is changed through the user interface\n',
    'onkeydown': 'onkeydown user depresses a key\n',
    'onkeypress': 'onkeypress user presses or holds down a key\n',
    'onkeyup': 'onkeyup user releases a key\n',
    'onlayoutcomplete': 'onlayoutcomplete user would have to print or print preview\n',
    'onload': 'onload attacker executes the attack string after the window loads\n',
    'onlosecapture': 'onlosecapture can be exploited by the releasecapture() method\n',
    'onmediacomplete': 'onmediacomplete when a streaming media file is used\n,'
                    ' this event could fire \nbefore the file starts playing\n',
    'onmediaerror': 'onmediaerror user opens a page in the browser that contains a media file\n, '
                 'and the event fires when there is a problem\n',
    'onmessage': 'onmessage fire when the document received a message\n',
    'onmousedown': 'onmousedown the attacker would need to get the user to click on an image\n',
    'onmouseenter': 'onmouseenter cursor moves over an object or area\n',
    'onmouseleave': 'onmouseleave the attacker would need to get the user to mouse over an \n'
                 'image or table and then off again\n',
    'onmousemove': 'onmousemove the attacker would need to get the user to mouse over an image or table\n',
    'onmouseout': 'onmouseout the attacker would need to get the user to mouse over an image or table and then off again\n',
    'onmouseover': 'onmouseover cursor moves over an object or area\n',
    'onmouseup': 'onmouseup the attacker would need to get the user to click on an image\n',
    'onmousewheel': 'onmousewheel the attacker would need to get the user to use their mouse wheel\n',
    'onmove': 'onmove user or attacker would move the page\n',
    'onmoveend': 'onmoveend user or attacker would move the page\n',
    'onmovestart': 'onmovestart user or attacker would move the page\n',
    'onoffline': 'onoffline occurs if the browser is working in online mode and it starts to work offline\n',
    'ononline': 'ononline occurs if the browser is working in offline mode and it starts to work online\n',
    'onoutofsync': 'onoutofsync interrupt the element’s ability to play its media as defined by the timeline\n',
    'onpaste': 'onpaste user would need to paste or attacker could use the execcommand("paste") function\n',
    'onpause': 'onpause the onpause event fires on every element that is active when the timeline pauses\n,'
            '\n including the body element\n',
    'onpopstate': 'onpopstate fires when user navigated the session history\n',
    'onprogress': 'onprogress attacker would use this as a flash movie was loading\n',
    'onpropertychange': 'onpropertychange user or attacker would need to change an element property\n',
    'onreadystatechange': 'onreadystatechange user or attacker would need to change an element property\n',
    'onredo': 'onredo user went forward in undo transaction history\n',
    'onrepeat': 'onrepeat the event fires once for each repetition of the timeline\n,'
             ' excluding the first full cycle\n',
    'onreset': 'onreset user or attacker resets a form\n',
    'onresize': 'onresize user would resize the window; attacker could auto initialize with something like:\n '
             '<script>self.resizeto(500\n,400);</script>\n',
    'onresizeend': 'onresizeend user would resize the window; attacker could auto initialize with something like:\n '
                '<script>self.resizeto(500\n,400);</script>\n',
    'onresizestart': 'onresizestart user would resize the window; attacker could auto initialize with something like:\n '
                  '<script>self.resizeto(500\n,400);</script>\n',
    'onresume': 'onresume the onresume event fires on every element that becomes active when the timeline resumes\n,'
             '\n including the body element\n',
    'onreverse': 'onreverse if the element has a repeatcount greater than one\n,'
              ' this event fires every \ntime the timeline begins to play backward\n',
    'onrowsenter': 'onrowsenter user or attacker would need to change a row in a data source\n',
    'onrowexit': 'onrowexit user or attacker would need to change a row in a data source\n',
    'onrowdelete': 'onrowdelete user or attacker would need to delete a row in a data source\n',
    'onrowinserted': 'onrowinserted user or attacker would need to insert a row in a data source\n',
    'onscroll': 'onscroll user would need to scroll\n, or attacker could use the scrollby() function\n',
    'onseek': 'onseek the onreverse event fires when the timeline is set to play in any direction other than forward\n',
    'onselect': 'onselect user needs to select some text - attacker could auto initialize with something like: \n'
             'window.document.execcommand("selectall");\n',
    'onselectionchange': 'onselectionchange user needs to select some text - attacker could auto initialize\n'
                      ' with something like: window.document.execcommand("selectall");\n',
    'onselectstart': 'onselectstart user needs to select some text - attacker could auto initialize with \n'
                  'something like: window.document.execcommand("selectall");\n',
    'onstart': 'onstart fires at the beginning of each marquee loop\n',
    'onstop': 'onstop user would need to press the stop button or leave the webpage\n',
    'onstorage': 'onstorage storage area changed\n',
    'onsyncrestored': 'onsyncrestored user interrupts the element’s ability to play its media as defined by the timeline to fire\n',
    'onsubmit': 'onsubmit requires attacker or user submits a form\n',
    'ontimeerror': 'ontimeerror user or attacker sets a time property\n,'
                ' such as dur\n, to an invalid value\n',
    'ontrackchange': 'ontrackchange user or attacker changes track in a playlist\n',
    'onundo': 'onundo user went backward in undo transaction history\n',
    'onunload': 'onunload as the user clicks any link or presses the back button or attacker forces a click\n',
    'onurlflip': 'onurlflip this event fires when an advanced streaming format (asf) file\n,'
              ' played by a html+time\n (timed interactive multimedia extensions) media tag\n,'
              ' processes script commands embedded in the asf file\n',
    'seeksegmenttime': 'seeksegmenttime this is a method that locates the specified point on the element’s segment time line \n'
                    'and begins playing from that point. the segment consists of one \n'
                    'repetition of the time line including reverse play using the autoreverse\n',
    'html_break': 'html breaks like " or ;, can use the attacker to stop current statement\n'
                 'and create his own\n',
    'hash_location': 'location.hash variable return to the attacker the location of the hash table with info\n'
                     'about the users. so he can watch and use this information very badly\n',
    'self_contained_payload': 'The name "Self-contained XSS" explains it all.\n'
                              ' It is a Cross-site scripting attack that does not require\n'
                              ' vulnerable web resource to echo input. Everything that is needed is \n'
                              'contained in a single URL.\n'
                              ' Once this URL is executed the resource will be automatically assembled.\n',
    'c_style_loops': 'Attacker can use c-style loops\n'
                     'like for or while loops, in order to execute piece of malicious code\n'
                     'in the server side',
    'c_style_short_condition': 'c-style short if condition, for example\n'
                               '1=1 ? true : false, can be very useful for the attacker in order to execute code on server\n',
    'jquery_selector': 'jquery selector like alert($(variable)), can show the attacker\n'
                       'value of sensitive variables, that can give him useful information about the server\n',
    'conditional_tokens': 'conditional tokens, like cc_on, can write on comment in javascript\n'
                          'and still be execute and give some information, for example about the version of the browser\n'
                          'the server running\n',
    'fire_fox_url_handler': 'the firefox url handler can cause some bugs and issue on the client\n'
                            'side, for preventing it, we just consider this option as a minimal hack try\n'
}

links_for_info = "For more information about XXE, check the following links:\n" \
                 "https://owasp.org/www-community/attacks/xss/\n" \
                 "https://portswigger.net/web-security/cross-site-scripting\n"
