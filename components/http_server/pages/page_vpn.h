/* VPN page templates */
/* VPN Page - Chunked for streaming */
#define VPN_CHUNK_HEAD "<html>\
<head>\
<meta name='viewport' content='width=device-width, initial-scale=1, maximum-scale=1, user-scalable=0'>\
<meta charset='UTF-8'>\
<title>WireGuard VPN</title>\
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
input[type='text'], input[type='number'], input[type='password'] { width: 100%; background: rgba(22, 33, 62, 0.6); border: 1px solid rgba(0, 217, 255, 0.2); border-radius: 8px; color: #e0e0e0; padding: 0.75rem; font-size: 0.95rem; }\
input[type='text']:focus, input[type='number']:focus, input[type='password']:focus, select:focus { outline: none; border-color: #00d9ff; box-shadow: 0 0 0 3px rgba(0, 217, 255, 0.1); background: rgba(22, 33, 62, 0.8); }\
input::placeholder { color: #666; }\
select { width: 100%; background: rgba(22, 33, 62, 0.6); border: 1px solid rgba(0, 217, 255, 0.2); border-radius: 8px; color: #e0e0e0; padding: 0.75rem; font-size: 0.95rem; cursor: pointer; -webkit-appearance: none; -moz-appearance: none; appearance: none; background-image: url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8'%3E%3Cpath d='M1 1l5 5 5-5' stroke='%2300d9ff' stroke-width='1.5' fill='none'/%3E%3C/svg%3E\"); background-repeat: no-repeat; background-position: right 0.75rem center; padding-right: 2rem; }\
select option { background: #16213e; color: #e0e0e0; }\
.ok-button { border: none; border-radius: 8px; padding: 0.75rem 1.5rem; font-size: 0.95rem; font-weight: 600; cursor: pointer; width: 100%; margin-top: 0.5rem; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #fff; box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4); }\
.status-table { background: rgba(22, 33, 62, 0.6); border-radius: 12px; padding: 1rem; margin: 1rem 0; border: 1px solid rgba(0, 217, 255, 0.1); }\
.status-table table { width: 100%; }\
.status-table td { padding: 0.75rem 0.5rem; font-size: 0.95rem; border-bottom: 1px solid rgba(255, 255, 255, 0.05); }\
.status-table tr:last-child td { border-bottom: none; }\
.status-table td:first-child { color: #888; text-align: right; padding-right: 1rem; width: 45%; font-size: 0.9rem; }\
.status-table td:last-child { color: #e0e0e0; font-weight: 500; }\
small { display: block; color: #888; font-size: 0.85rem; margin-top: 0.5rem; line-height: 1.4; }\
@media (max-width: 600px) { body { padding: 0.5rem; } #container { padding: 1rem; } h1 { font-size: 1.25rem; } h2 { font-size: 1rem; } td:first-child { font-size: 0.8rem; width: 40%; } input[type='text'], input[type='number'], input[type='password'], select { font-size: 0.9rem; padding: 0.65rem; } .ok-button { font-size: 0.9rem; padding: 0.65rem 1.25rem; } }\
</style>\
<body>\
<div id='container'>\
<div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;'>\
<div style='display: flex; align-items: center;'>\
<a href='/' style='display: inline-block; margin-right: 1rem;'><img src='/favicon.png' alt='Home' style='width: 64px; height: 64px; border: none;'></a>\
<h1 style='margin: 0;'>WireGuard VPN</h1>\
</div>"

#define VPN_CHUNK_MID "\
</div>\
<script>\
var qs = window.location.search.substr(1);\
if (qs.indexOf('vpn_enabled=') !== -1 || qs.indexOf('vpn_privkey=') !== -1) {\
document.getElementById('container').style.display = 'none';\
document.body.innerHTML ='<div id=\"container\"><h1>WireGuard VPN</h1><p style=\"text-align:center; margin: 2rem 0; color: #00d9ff;\">Settings saved! Rebooting...</p></div>';\
setTimeout(\"location.href = '/'\", 10000);\
}\
</script>"

/* VPN form - static wrapper (no format strings) */
#define VPN_CHUNK_FORM_OPEN "\
<h2>Configuration</h2>\
<form action='/vpn' method='GET'>\
<table>"

#define VPN_CHUNK_FORM_CLOSE "\
<tr><td></td><td><input type='submit' value='Save &amp; Reboot' class='ok-button'/></td></tr>\
</table>\
</form>\
<div style='margin-top: 1.5rem; text-align: center;'>\
<a href='/' style='padding: 0.6rem 1.5rem; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #fff; border: none; border-radius: 8px; text-decoration: none; font-size: 0.9rem; font-weight: 600;'>Home</a>\
</div>\
</div>\
</body>\
</html>"

