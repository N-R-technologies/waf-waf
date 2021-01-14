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
    'fscommand': 'attacker can use this when executed from within an embedded flash object\n',
    'onabort': 'when user aborts the loading of an image\n',
    'onactivate': 'when object is set as the active element\n',
    'onafterprint': 'activates after user prints or previews print job\n',
    'onafterupdate': 'activates on data object after updating data in the source object\n',
    'onbeforeactivate': 'fires before the object is set as the active element\n',
    'onbeforecopy': 'attacker executes the attack string right before a selection is copied to the clipboard\n'
                    ' - attackers can do this with the execcommand("copy") function\n',
    'onbeforecut': 'attacker executes the attack string right before a selection is cut\n',
    'onbeforedeactivate': 'fires right after the activeelement is changed from the current object\n',
    'onbeforeeditfocus': 'fires before an object contained in an editable element enters a\n'
                         'ui-activated state or when an editable container object is control selected\n',
    'onbeforepaste': 'user needs to be tricked into pasting or be forced into it using the execcommand("paste")\n'
                     ' function\n',
    'onbeforeprint': 'user would need to be tricked into printing or attacker could use the print()\n'
                     ' or execcommand("print") function)\n',
    'onbeforeunload': 'user would need to be tricked into closing the browser - attacker cannot unload\n'
                      ' windows unless it was spawned from the parent\n',
    'onbeforeupdate': 'activates on data object before updating data in the source object\n',
    'onbegin': 'the onbegin event fires immediately when the element’s timeline begins\n',
    'onblur': 'in the case where another popup is loaded and window looses focus\n',
    'onbounce': 'fires when the behavior property of the marquee object is set to “alternate” and the\n'
                ' contents of the marquee reach one side of the window\n',
    'oncellchange': 'fires when data changes in the data provider\n',
    'onchange': 'select\n, text\n, or textarea field loses focus and its value has been modified\n',
    'onclick': 'someone clicks on a form\n', 'oncontextmenu': 'user would need to right click on attack area\n',
    'oncontrolselect': 'fires when the user is about to make a control selection of the object\n',
    'oncopy': 'user needs to copy something or it can be exploited using the execcommand("copy") command\n',
    'oncut': 'user needs to copy something or it can be exploited using the execcommand("cut") command\n',
    'ondataavailable': 'user would need to change data in an element\n, or attacker could perform the same function\n',
    'ondatasetchanged': 'fires when the data set exposed by a data source object changes\n',
    'ondatasetcomplete': 'fires to indicate that all data is available from the data source object\n',
    'ondblclick': 'user double-clicks a form element or a link\n',
    'ondeactivate': 'fires when the activeelement is changed from the current object to another\n'
                    ' object in the parent document\n',
    'ondrag': 'requires that the user drags an object\n', 
    'ondragend': 'requires that\n the user drags an object\n',
    'ondragleave': 'requires that the user drags an object off a valid location\n',
    'ondragenter': 'requires that the user drags an object into a valid location\n',
    'ondragover': 'requires that the user drags an object into a valid location\n',
    'ondragdrop': 'user drops an object (e.g. file) onto the browser window\n',
    'ondragstart': 'occurs when user starts drag operation\n',
    'ondrop': 'user drops an object (e.g. file) onto the browser window\n',
    'onend': 'the onend event fires when the timeline ends\n',
    'onerror': 'loading of a document or image causes an error\n',
    'onerrorupdate': 'fires on a databound object when an error occurs while updating the associated \n'
                     'data in the data source object\n',
    'onfilterchange': 'fires when a visual filter completes state change\n',
    'onfinish': 'attacker can create the exploit when marquee is finished looping\n',
    'onfocus': 'attacker executes the attack string when the window gets focus\n',
    'onfocusin': 'attacker executes the attack string when window gets focus\n',
    'onfocusout': 'attacker executes the attack string when window looses focus\n',
    'onhashchange': 'fires when the fragment identifier part of the document’s current address changed\n',
    'onhelp': 'attacker executes the attack string when users hits f1 while the window is in focus\n',
    'oninput': 'the text content of an element is changed through the user interface\n',
    'onkeydown': 'user depresses a key\n', 'onkeypress': 'user presses or holds down a key\n',
    'onkeyup': 'user releases a key\n', 'onlayoutcomplete': 'user would have to print or print preview\n',
    'onload': 'attacker executes the attack string after the window loads\n',
    'onlosecapture': 'can be exploited by the releasecapture() method\n',
    'onmediacomplete': 'when a streaming media file is used\n, this event could fire \n'
                       'before the file starts playing\n',
    'onmediaerror': 'user opens a page in the browser that contains a media file\n, \n'
                    'and the event fires when there is a problem\n',
    'onmessage': 'fire when the document received a message\n',
    'onmousedown': 'the attacker would need to get the user to click on an image\n',
    'onmouseenter': 'cursor moves over an object or area\n',
    'onmouseleave': 'the attacker would need to get the user to mouse over an \n'
                    'image or table and then off again\n',
    'onmousemove': 'the attacker would need to get the user to mouse over an image or table\n',
    'onmouseout': 'the attacker would need to get the user to mouse over an image or table and then off again\n',
    'onmouseover': 'cursor moves over an object or area\n',
    'onmouseup': 'the attacker would need to get the user to click on an image\n',
    'onmousewheel': 'the attacker would need to get the user to use their mouse wheel\n',
    'onmove': 'user or attacker would move the page\n',
    'onmoveend': 'user or attacker would move the page\n',
    'onmovestart': 'user or attacker would move the page\n',
    'onoffline': 'occurs if the browser is working in online mode and it starts to work offline\n',
    'ononline': 'occurs if the browser is working in offline mode and it starts to work online\n',
    'onoutofsync': 'interrupt the element’s ability to play its media as defined by the timeline\n',
    'onpaste': 'user would need to paste or attacker could use the execcommand("paste") function\n',
    'onpause': 'the onpause event fires on every element that is active when the timeline pauses\n,\n'
               ' including the body element\n',
    'onpopstate': 'fires when user navigated the session history\n',
    'onprogress': 'attacker would use this as a flash movie was loading\n',
    'onpropertychange': 'user or attacker would need to change an element property\n',
    'onreadystatechange': 'user or attacker would need to change an element property\n',
    'onredo': 'user went forward in undo transaction history\n',
    'onrepeat': 'the event fires once for each repetition of the timeline\n, excluding the first full cycle\n',
    'onreset': 'user or attacker resets a form\n',
    'onresize': 'user would resize the window; attacker could auto initialize with something like:\n'
                ' <script>self.resizeto(500\n,400);</script>\n',
    'onresizeend': 'user would resize the window; attacker could auto initialize with something like:\n'
                   ' <script>self.resizeto(500\n,400);</script>\n',
    'onresizestart': 'user would resize the window; attacker could auto initialize with something like:\n'
                     ' <script>self.resizeto(500\n,400);</script>\n',
    'onresume': 'the onresume event fires on every element that becomes active when the timeline resumes\n,\n'
                ' including the body element\n',
    'onreverse': 'if the element has a repeatcount greater than one\n, this event fires every \n'
                 'time the timeline begins to play backward\n',
    'onrowsenter': 'user or attacker would need to change a row in a data source\n',
    'onrowexit': 'user or attacker would need to change a row in a data source\n',
    'onrowdelete': 'user or attacker would need to delete a row in a data source\n',
    'onrowinserted': 'user or attacker would need to insert a row in a data source\n',
    'onscroll': 'user would need to scroll\n, or attacker could use the scrollby() function\n',
    'onseek': 'the onreverse event fires when the timeline is set to play in any direction other than forward\n',
    'onselect': 'user needs to select some text - attacker could auto initialize with something like: \n'
                'window.document.execcommand("selectall");\n',
    'onselectionchange': 'user needs to select some text - attacker could auto initialize\n'
                         ' with something like: window.document.execcommand("selectall");\n',
    'onselectstart': 'user needs to select some text - attacker could auto initialize with \n'
                     'something like: window.document.execcommand("selectall");\n',
    'onstart': 'fires at the beginning of each marquee loop\n',
    'onstop': 'user would need to press the stop button or leave the webpage\n',
    'onstorage': 'storage area changed\n',
    'onsyncrestored': 'user interrupts the element’s ability to play its media as defined by the timeline to fire\n',
    'onsubmit': 'requires attacker or user submits a form\n',
    'ontimeerror': 'user or attacker sets a time property\n, such as dur\n, to an invalid value\n',
    'ontrackchange': 'user or attacker changes track in a playlist\n',
    'onundo': 'user went backward in undo transaction history\n',
    'onunload': 'as the user clicks any link or presses the back button or attacker forces a click\n',
    'onurlflip': 'this event fires when an advanced streaming format (asf) file\n, played by a html+time\n'
                 ' (timed interactive multimedia extensions) media tag\n, processes script commands embedded in the asf file\n',
    'seeksegmenttime': 'this is a method that locates the specified point on the element’s segment time line \n'
                       'and begins playing from that point. the segment consists of one \n'
                       'repetition of the time line including reverse play using the autoreverse attribut'
}

links_for_info = "For more information about XXE, check the following links:\n" \
                 "https://owasp.org/www-community/attacks/xss/\n" \
                 "https://portswigger.net/web-security/cross-site-scripting\n"
