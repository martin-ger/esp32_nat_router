/* Getting Started page templates */
#include "router_config.h"

#if !CONFIG_ETH_UPLINK
/* Getting Started Page */
#define SETUP_CHUNK_HEAD "<html>\
<head>\
<meta name='viewport' content='width=device-width, initial-scale=1, maximum-scale=1, user-scalable=0'>\
<meta charset='UTF-8'>\
<title>Getting Started</title>\
<link rel='icon' href='favicon.png'>\
</head>\
<style>\
* { box-sizing: border-box; margin: 0; padding: 0; }\
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: #e0e0e0; padding: 1rem; min-height: 100vh; line-height: 1.6; }\
h1 { font-size: 1.5rem; font-weight: 600; color: #00d9ff; margin-bottom: 1rem; text-shadow: 0 0 20px rgba(0, 217, 255, 0.3); }\
h2 { font-size: 1.15rem; font-weight: 500; color: #00d9ff; margin: 1.5rem 0 0.75rem 0; padding-bottom: 0.5rem; border-bottom: 1px solid rgba(0, 217, 255, 0.2); }\
#container { max-width: 500px; margin: 0 auto; padding: 1.5rem; background: rgba(30, 30, 46, 0.9); border-radius: 16px; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4); backdrop-filter: blur(10px); }\
table { width: 100%; border-collapse: collapse; }\
td { padding: 0.5rem 0; vertical-align: top; }\
td:first-child { color: #888; font-size: 0.9rem; padding-right: 0.75rem; width: 35%; text-align: right; }\
input[type='text'], input[type='password'] { width: 100%; background: rgba(22, 33, 62, 0.6); border: 1px solid rgba(0, 217, 255, 0.2); border-radius: 8px; color: #e0e0e0; padding: 0.75rem; font-size: 0.95rem; }\
input[type='text']:focus, input[type='password']:focus { outline: none; border-color: #00d9ff; box-shadow: 0 0 0 3px rgba(0, 217, 255, 0.1); background: rgba(22, 33, 62, 0.8); }\
input::placeholder { color: #666; }\
.ok-button { border: none; border-radius: 8px; padding: 0.75rem 1.5rem; font-size: 0.95rem; font-weight: 600; cursor: pointer; width: 100%; margin-top: 0.5rem; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #fff; box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4); }\
.nav-link { display: inline-block; padding: 0.6rem 1.5rem; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #fff; border: none; border-radius: 8px; text-decoration: none; font-size: 0.9rem; font-weight: 600; margin-right: 0.5rem; }\
@media (max-width: 600px) { body { padding: 0.5rem; } #container { padding: 1rem; } h1 { font-size: 1.25rem; } h2 { font-size: 1rem; } td:first-child { font-size: 0.8rem; width: 40%; } input[type='text'], input[type='password'] { font-size: 0.9rem; padding: 0.65rem; } .ok-button { font-size: 0.9rem; padding: 0.65rem 1.25rem; } }\
</style>\
<body>\
<div id='container'>\
<div style='display: flex; align-items: center; margin-bottom: 0.5rem;'>\
<a href='/' style='display: inline-block; margin-right: 1rem;'><img src='/favicon.png' alt='Home' style='width: 64px; height: 64px; border: none;'></a>\
<h1 style='margin: 0;'>Getting Started</h1>\
</div>\
<script>\
var qs = window.location.search.substr(1);\
if (qs.indexOf('ap_ssid=') !== -1 || (qs.indexOf('ssid=') !== -1 && qs.indexOf('password=') !== -1)) {\
document.getElementById('container').style.display = 'none';\
document.body.innerHTML ='<div id=\"container\"><h1>Getting Started</h1><p style=\"text-align:center; margin: 2rem 0; color: #00d9ff;\">Settings saved! Rebooting...</p></div>';\
setTimeout(\"location.href = '/'\", 10000);\
}\
</script>"

/* Setup form - uses: safe_ap_ssid, safe_ssid */
#define SETUP_CHUNK_FORM "\
<form action='/setup' method='GET'>\
<h2>Access Point</h2>\
<table>\
<tr><td>SSID</td><td><input type='text' name='ap_ssid' value='%s' placeholder='Hotspot name'/></td></tr>\
<tr><td>Password</td><td><input type='password' name='ap_password' placeholder='unchanged'/></td></tr>\
</table>\
<h2>Uplink (Internet)</h2>\
<table>\
<tr><td>SSID</td><td><input type='text' name='ssid' value='%s' placeholder='WiFi network'/></td></tr>\
<tr><td>Password</td><td><input type='password' name='password' placeholder='unchanged'/></td></tr>\
<tr><td></td><td><input type='submit' value='Save &amp; Reboot' class='ok-button'/></td></tr>\
</table>\
</form>\
<div style='margin-top: 1.5rem; text-align: center;'>\
<a href='/scan' class='nav-link'>📡 WiFi Scan</a>\
<a href='/' class='nav-link'>🏠 Home</a>\
</div>\
</div>\
</body>\
</html>"
#endif /* !CONFIG_ETH_UPLINK */
