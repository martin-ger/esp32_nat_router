//#include "esp_idf_version.h"
#include "router_globals.h"

/* Index Page - System Status with navigation buttons */
#define INDEX_PAGE "<html>\
<head>\
<meta name='viewport' content='width=device-width, initial-scale=1, maximum-scale=1, user-scalable=0'>\
<meta charset='UTF-8'>\
<title>ESP32 NAT Router</title>\
<link rel='icon' href='favicon.png'>\
</head>\
<style>\
* {\
box-sizing: border-box;\
margin: 0;\
padding: 0;\
}\
\
body {\
font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;\
background: linear-gradient(135deg, #1a1a2e 0%%, #16213e 100%%);\
color: #e0e0e0;\
padding: 1rem;\
min-height: 100vh;\
line-height: 1.6;\
}\
\
h1 {\
font-size: 1.75rem;\
font-weight: 600;\
color: #00d9ff;\
margin-bottom: 0.5rem;\
text-align: center;\
text-shadow: 0 0 20px rgba(0, 217, 255, 0.3);\
}\
\
h2 {\
font-size: 1.25rem;\
font-weight: 500;\
color: #00d9ff;\
margin: 1.5rem 0 1rem 0;\
}\
\
#container {\
max-width: 600px;\
margin: 0 auto;\
padding: 1.5rem;\
background: rgba(30, 30, 46, 0.9);\
border-radius: 16px;\
box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);\
backdrop-filter: blur(10px);\
}\
\
.status-table {\
background: rgba(22, 33, 62, 0.6);\
border-radius: 12px;\
padding: 1rem;\
margin: 1rem 0;\
border: 1px solid rgba(0, 217, 255, 0.1);\
}\
\
.status-table table {\
width: 100%%;\
border-collapse: collapse;\
}\
\
.status-table td {\
padding: 0.75rem 0.5rem;\
font-size: 0.95rem;\
border-bottom: 1px solid rgba(255, 255, 255, 0.05);\
}\
\
.status-table tr:last-child td {\
border-bottom: none;\
}\
\
.status-table td:first-child {\
color: #888;\
text-align: right;\
padding-right: 1rem;\
width: 45%%;\
font-size: 0.9rem;\
}\
\
.status-table td:last-child {\
color: #e0e0e0;\
font-weight: 500;\
}\
\
.button-container {\
display: grid;\
grid-template-columns: 1fr 1fr;\
gap: 1rem;\
margin: 2rem 0 1rem 0;\
}\
\
.nav-button {\
background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);\
color: #fff;\
border: none;\
border-radius: 12px;\
padding: 1.25rem 1rem;\
font-size: 1rem;\
font-weight: 600;\
text-decoration: none;\
display: flex;\
align-items: center;\
justify-content: center;\
cursor: pointer;\
transition: all 0.3s ease;\
box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);\
text-align: center;\
}\
\
.nav-button:hover {\
transform: translateY(-2px);\
box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);\
}\
\
.nav-button:active {\
transform: translateY(0);\
}\
\
@media (max-width: 600px) {\
body {\
padding: 0.5rem;\
}\
\
#container {\
padding: 1rem;\
border-radius: 12px;\
}\
\
h1 {\
font-size: 1.5rem;\
}\
\
h2 {\
font-size: 1.1rem;\
}\
\
.button-container {\
grid-template-columns: 1fr;\
gap: 0.75rem;\
}\
\
.status-table td {\
padding: 0.5rem 0.25rem;\
font-size: 0.85rem;\
}\
\
.status-table td:first-child {\
width: 50%%;\
font-size: 0.8rem;\
}\
}\
</style>\
<body>\
<div id='container'>\
<div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;'>\
<div style='display: flex; align-items: center;'>\
<a href='/' style='display: inline-block; margin-right: 1rem;'><img src='/favicon.png' alt='Home' style='width: 64px; height: 64px; border: none;'></a>\
<h1 style='margin: 0;'>ESP32 NAT Router</h1>\
</div>\
%s\
</div>\
<h2>System Status</h2>\
<div class='status-table'>\
<table>\
<tr>\
<td>Uptime:</td>\
<td>%s</td>\
</tr>\
<tr>\
<td>Connection:</td>\
<td><strong>%s</strong></td>\
</tr>\
<tr>\
<td>STA IP:</td>\
<td>%s</td>\
</tr>\
<tr>\
<td>AP IP:</td>\
<td>%s</td>\
</tr>\
<tr>\
<td>DHCP Pool:</td>\
<td>%s</td>\
</tr>\
<tr>\
<td>Clients:</td>\
<td>%d</td>\
</tr>\
<tr>\
<td>Bytes Sent:</td>\
<td>%.1f MB</td>\
</tr>\
<tr>\
<td>Bytes Received:</td>\
<td>%.1f MB</td>\
</tr>\
<tr>\
<td>PCAP Capture:</td>\
<td>%s</td>\
</tr>\
</table>\
</div>\
<div class='button-container'>\
<a href='/config' class='nav-button'>⚙️ Configuration</a>\
<a href='/mappings' class='nav-button'>🔀 Mappings</a>\
<a href='/firewall' class='nav-button'>🛡️ Firewall</a>\
<link rel='icon' type='image/png' href='/favicon.png'>\
</div>\
%s\
<div style='margin-top: 2rem; padding-top: 1rem; border-top: 1px solid rgba(255, 255, 255, 0.1); text-align: center;'>\
<span style='color: #666; font-size: 0.75rem; font-family: monospace;'>v"\
ROUTER_VERSION\
" | Build: "\
__DATE__\
" | ESP-IDF: "\
IDF_VER\
" | <a href='https://github.com/martin-ger/esp32_nat_router' target='_blank' rel='noopener' style='color: #00d9ff; text-decoration: none;'>Source</a></span>\
</div>\
</div>\
</body>\
</html>\
"

/* Configuration Page - WiFi settings and MAC addresses */
#define ROUTER_CONFIG_PAGE "<html>\
<head>\
<meta name='viewport' content='width=device-width, initial-scale=1, maximum-scale=1, user-scalable=0'>\
<meta charset='UTF-8'>\
<title>Configuration</title>\
<link rel='icon' href='favicon.png'>\
</head>\
<style>\
* {\
box-sizing: border-box;\
margin: 0;\
padding: 0;\
}\
\
body {\
font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;\
background: linear-gradient(135deg, #1a1a2e 0%%, #16213e 100%%);\
color: #e0e0e0;\
padding: 1rem;\
min-height: 100vh;\
line-height: 1.6;\
}\
\
h1 {\
font-size: 1.5rem;\
font-weight: 600;\
color: #00d9ff;\
margin-bottom: 1rem;\
text-shadow: 0 0 20px rgba(0, 217, 255, 0.3);\
}\
\
h2 {\
font-size: 1.15rem;\
font-weight: 500;\
color: #00d9ff;\
margin: 1.5rem 0 0.75rem 0;\
padding-bottom: 0.5rem;\
border-bottom: 1px solid rgba(0, 217, 255, 0.2);\
}\
\
#container {\
max-width: 500px;\
margin: 0 auto;\
padding: 1.5rem;\
background: rgba(30, 30, 46, 0.9);\
border-radius: 16px;\
box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);\
backdrop-filter: blur(10px);\
}\
\
.nav-link {\
color: #00d9ff;\
text-decoration: none;\
font-size: 0.9rem;\
display: inline-block;\
margin-bottom: 1rem;\
transition: all 0.2s;\
}\
\
.nav-link:hover {\
color: #33e0ff;\
transform: translateX(-3px);\
}\
\
form {\
margin-bottom: 1.5rem;\
}\
\
table {\
width: 100%%;\
border-collapse: collapse;\
}\
\
td {\
padding: 0.5rem 0;\
vertical-align: top;\
}\
\
td:first-child {\
color: #888;\
font-size: 0.9rem;\
padding-right: 0.75rem;\
width: 35%%;\
text-align: right;\
}\
\
input[type='text'], input[type='password'] {\
width: 100%%;\
background: rgba(22, 33, 62, 0.6);\
border: 1px solid rgba(0, 217, 255, 0.2);\
border-radius: 8px;\
color: #e0e0e0;\
padding: 0.75rem;\
font-size: 0.95rem;\
transition: all 0.3s;\
}\
\
input:focus {\
outline: none;\
border-color: #00d9ff;\
box-shadow: 0 0 0 3px rgba(0, 217, 255, 0.1);\
background: rgba(22, 33, 62, 0.8);\
}\
\
input::placeholder {\
color: #666;\
}\
\
.ok-button, .red-button {\
border: none;\
border-radius: 8px;\
padding: 0.75rem 1.5rem;\
font-size: 0.95rem;\
font-weight: 600;\
cursor: pointer;\
transition: all 0.3s;\
width: 100%%;\
margin-top: 0.5rem;\
}\
\
.ok-button {\
background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);\
color: #fff;\
box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);\
}\
\
.ok-button:hover {\
transform: translateY(-2px);\
box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);\
}\
\
.red-button {\
background: linear-gradient(135deg, #f093fb 0%%, #f5576c 100%%);\
color: #fff;\
box-shadow: 0 4px 15px rgba(245, 87, 108, 0.4);\
}\
\
.red-button:hover {\
transform: translateY(-2px);\
box-shadow: 0 6px 20px rgba(245, 87, 108, 0.6);\
}\
\
small {\
display: block;\
color: #888;\
font-size: 0.85rem;\
margin-top: 0.5rem;\
line-height: 1.4;\
}\
\
@media (max-width: 600px) {\
body {\
padding: 0.5rem;\
}\
\
#container {\
padding: 1rem;\
border-radius: 12px;\
}\
\
h1 {\
font-size: 1.25rem;\
}\
\
h2 {\
font-size: 1rem;\
}\
\
td:first-child {\
font-size: 0.8rem;\
width: 40%%;\
}\
\
input[type='text'], input[type='password'] {\
font-size: 0.9rem;\
padding: 0.65rem;\
}\
\
.ok-button, .red-button {\
font-size: 0.9rem;\
padding: 0.65rem 1.25rem;\
}\
}\
</style>\
<body>\
<div id='container'>\
<div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;'>\
<div style='display: flex; align-items: center;'>\
<a href='/' style='display: inline-block; margin-right: 1rem;'><img src='/favicon.png' alt='Home' style='width: 64px; height: 64px; border: none;'></a>\
<h1 style='margin: 0;'>Configuration</h1>\
</div>\
%s\
</div>\
<script>\
if (window.location.search.substr(1) != '') {\
document.getElementById('container').style.display = 'none';\
document.body.innerHTML ='<div id=\"container\"><h1>Configuration</h1><p style=\"text-align:center; margin: 2rem 0; color: #00d9ff;\">Settings saved! Rebooting...</p></div>';\
setTimeout(\"location.href = '/'\", 10000);\
}\
</script>\
<h2>Access Point Settings</h2>\
<form action='' method='GET'>\
<table>\
<tr>\
<td>SSID</td>\
<td><input type='text' name='ap_ssid' value='%s' placeholder='Network name'/></td>\
</tr>\
<tr>\
<td>Password</td>\
<td><input type='text' name='ap_password' value='%s' placeholder='Min 8 chars or empty'/></td>\
</tr>\
<tr>\
<td>AP IP Address</td>\
<td><input type='text' name='ap_ip_addr' value='%s' placeholder='192.168.4.1'/></td>\
</tr>\
<tr>\
<td>MAC Address</td>\
<td><input type='text' name='ap_mac' value='%s' placeholder='AA:BB:CC:DD:EE:FF'/></td>\
</tr>\
<tr>\
<td></td>\
<td><input type='submit' value='Apply' class='ok-button'/></td>\
</tr>\
</table>\
<small>Leave password empty for open network</small>\
</form>\
\
<h2>Station Settings (Uplink)</h2>\
<form action='' method='GET'>\
<table>\
<tr>\
<td>SSID</td>\
<td><input type='text' name='ssid' value='%s' placeholder='Uplink network'/></td>\
</tr>\
<tr>\
<td>Password</td>\
<td><input type='text' name='password' value='%s' placeholder='Network password'/></td>\
</tr>\
<tr>\
<td colspan='2' style='padding-top: 1rem; color: #888; font-size: 0.85rem;'>WPA2 Enterprise (optional)</td>\
</tr>\
<tr>\
<td>Username</td>\
<td><input type='text' name='ent_username' value='%s' placeholder='Enterprise username'/></td>\
</tr>\
<tr>\
<td>Identity</td>\
<td><input type='text' name='ent_identity' value='%s' placeholder='Enterprise identity'/></td>\
</tr>\
<tr>\
<td>MAC Address</td>\
<td><input type='text' name='sta_mac' value='%s' placeholder='AA:BB:CC:DD:EE:FF'/></td>\
</tr>\
<tr>\
<td></td>\
<td><input type='submit' value='Connect' class='ok-button'/></td>\
</tr>\
</table>\
</form>\
\
<h2>Static IP Settings</h2>\
<form action='' method='GET'>\
<table>\
<tr>\
<td>Static IP</td>\
<td><input type='text' name='staticip' value='%s' placeholder='192.168.1.100'/></td>\
</tr>\
<tr>\
<td>Subnet Mask</td>\
<td><input type='text' name='subnetmask' value='%s' placeholder='255.255.255.0'/></td>\
</tr>\
<tr>\
<td>Gateway</td>\
<td><input type='text' name='gateway' value='%s' placeholder='192.168.1.1'/></td>\
</tr>\
<tr>\
<td></td>\
<td><input type='submit' value='Set Static IP' class='ok-button'/></td>\
</tr>\
</table>\
<small>Leave empty for DHCP</small>\
</form>\
\
<h2>PCAP Packet Capture</h2>\
<form action='' method='GET'>\
<table>\
<tr>\
<td>Mode</td>\
<td>\
<select name='pcap_mode' style='padding: 0.4rem; border-radius: 4px; border: 1px solid #ccc;'>\
<option value='off' %s>Off</option>\
<option value='acl' %s>ACL Monitor</option>\
<option value='promisc' %s>Promiscuous</option>\
</select>\
<input type='submit' value='Set' class='ok-button' style='margin-left: 0.5rem;'/>\
</td>\
</tr>\
<tr>\
<td>Client</td>\
<td><strong style='color: %s;'>%s</strong></td>\
</tr>\
<tr>\
<td>Stats</td>\
<td>%lu captured, %lu dropped</td>\
</tr>\
</table>\
</form>\
<form action='' method='GET'>\
<table>\
<tr>\
<td>Snaplen</td>\
<td><input type='text' name='pcap_snaplen' value='%d' placeholder='64-1600'/></td>\
</tr>\
<tr>\
<td></td>\
<td><input type='submit' value='Set Snaplen' class='ok-button'/></td>\
</tr>\
</table>\
<small>Max bytes to capture per packet (64-1600). Lower values save buffer space.</small>\
</form>\
\
<h2>Device Management</h2>\
<form action='' method='GET'>\
<table>\
<tr>\
<td>Device</td>\
<td><input type='submit' name='reset' value='Reboot Now' class='red-button'/></td>\
</tr>\
</table>\
</form>\
\
<div style='margin-top: 2rem; padding: 1rem; background: #fff3cd; border: 2px solid #ff9800; border-radius: 8px;'>\
<h2 style='color: #ff6b00; margin-bottom: 0.5rem;'>⚠ Danger Zone</h2>\
<p style='margin-bottom: 1rem; color: #666; font-size: 0.9rem;'>This will disable the web interface completely. You can only re-enable it via the serial console using the 'enable' command.</p>\
<form action='' method='GET'>\
<table>\
<tr>\
<td style='color: #d32f2f; font-weight: bold;'>Disable Interface</td>\
<td><input type='submit' name='disable_interface' value='Disable' class='red-button' onclick='return confirm(\"Are you sure? The web interface will be disabled and can only be enabled via serial console with the enable command.\");'/></td>\
</tr>\
</table>\
</form>\
</div>\
<div style='margin-top: 2rem; text-align: center;'>\
<a href='/' style='padding: 0.75rem 2rem; background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: #fff; border: none; border-radius: 8px; text-decoration: none; font-size: 0.95rem; font-weight: 600; cursor: pointer; transition: all 0.3s; box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4); display: inline-block;'>🏠 Home</a>\
</div>\
</div>\
</body>\
</html>\
"

/* Mappings Page (DHCP Reservations + Port Forwarding) */
#define MAPPINGS_PAGE "<html>\
<head>\
<meta name='viewport' content='width=device-width, initial-scale=1, maximum-scale=1, user-scalable=0'>\
<meta charset='UTF-8'>\
<title>Mappings</title>\
<link rel='icon' href='favicon.png'>\
</head>\
<style>\
* {\
box-sizing: border-box;\
margin: 0;\
padding: 0;\
}\
\
body {\
font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;\
background: linear-gradient(135deg, #1a1a2e 0%%, #16213e 100%%);\
color: #e0e0e0;\
padding: 1rem;\
min-height: 100vh;\
line-height: 1.6;\
}\
\
h1 {\
font-size: 1.5rem;\
font-weight: 600;\
color: #00d9ff;\
margin-bottom: 1rem;\
text-shadow: 0 0 20px rgba(0, 217, 255, 0.3);\
}\
\
h2 {\
font-size: 1.15rem;\
font-weight: 500;\
color: #00d9ff;\
margin: 1.5rem 0 0.75rem 0;\
padding-bottom: 0.5rem;\
border-bottom: 1px solid rgba(0, 217, 255, 0.2);\
}\
\
#container {\
max-width: 800px;\
margin: 0 auto;\
padding: 1.5rem;\
background: rgba(30, 30, 46, 0.9);\
border-radius: 16px;\
box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);\
backdrop-filter: blur(10px);\
}\
\
.nav-link {\
color: #00d9ff;\
text-decoration: none;\
font-size: 0.9rem;\
display: inline-block;\
margin-bottom: 1rem;\
transition: all 0.2s;\
}\
\
.nav-link:hover {\
color: #33e0ff;\
transform: translateX(-3px);\
}\
\
.data-table {\
width: 100%%;\
border-collapse: collapse;\
margin: 1rem 0;\
background: rgba(22, 33, 62, 0.6);\
border-radius: 12px;\
overflow: hidden;\
border: 1px solid rgba(0, 217, 255, 0.1);\
}\
\
.data-table thead {\
background: rgba(0, 217, 255, 0.1);\
}\
\
.data-table th {\
padding: 0.75rem 0.5rem;\
text-align: left;\
font-weight: 600;\
color: #00d9ff;\
font-size: 0.9rem;\
}\
\
.data-table td {\
padding: 0.75rem 0.5rem;\
border-bottom: 1px solid rgba(255, 255, 255, 0.05);\
font-size: 0.9rem;\
}\
\
.data-table tbody tr:last-child td {\
border-bottom: none;\
}\
\
.data-table tbody tr:hover {\
background: rgba(0, 217, 255, 0.05);\
}\
\
table {\
width: 100%%;\
border-collapse: collapse;\
}\
\
td {\
padding: 0.5rem 0;\
vertical-align: top;\
}\
\
td:first-child {\
color: #888;\
font-size: 0.9rem;\
padding-right: 0.75rem;\
width: 30%%;\
text-align: right;\
}\
\
input[type='text'], input[type='number'], select {\
width: 100%%;\
background: rgba(22, 33, 62, 0.6);\
border: 1px solid rgba(0, 217, 255, 0.2);\
border-radius: 8px;\
color: #e0e0e0;\
padding: 0.75rem;\
font-size: 0.95rem;\
transition: all 0.3s;\
}\
\
input:focus, select:focus {\
outline: none;\
border-color: #00d9ff;\
box-shadow: 0 0 0 3px rgba(0, 217, 255, 0.1);\
background: rgba(22, 33, 62, 0.8);\
}\
\
input::placeholder {\
color: #666;\
}\
\
select {\
cursor: pointer;\
}\
\
.ok-button {\
background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);\
color: #fff;\
border: none;\
border-radius: 8px;\
padding: 0.75rem 1.5rem;\
font-size: 0.95rem;\
font-weight: 600;\
cursor: pointer;\
transition: all 0.3s;\
box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);\
width: 100%%;\
margin-top: 0.5rem;\
}\
\
.ok-button:hover {\
transform: translateY(-2px);\
box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6);\
}\
\
.red-button {\
background: linear-gradient(135deg, #f093fb 0%%, #f5576c 100%%);\
color: #fff;\
border: none;\
border-radius: 6px;\
padding: 0.4rem 0.8rem;\
font-size: 0.8rem;\
font-weight: 600;\
cursor: pointer;\
transition: all 0.3s;\
box-shadow: 0 2px 8px rgba(245, 87, 108, 0.4);\
text-decoration: none;\
display: inline-block;\
}\
\
.red-button:hover {\
transform: translateY(-1px);\
box-shadow: 0 4px 12px rgba(245, 87, 108, 0.6);\
}\
\
.section {\
margin-bottom: 2rem;\
}\
\
@media (max-width: 768px) {\
body {\
padding: 0.5rem;\
}\
\
#container {\
padding: 1rem;\
border-radius: 12px;\
}\
\
h1 {\
font-size: 1.25rem;\
}\
\
h2 {\
font-size: 1rem;\
}\
\
.data-table {\
font-size: 0.8rem;\
display: block;\
overflow-x: auto;\
}\
\
.data-table th,\
.data-table td {\
padding: 0.5rem 0.25rem;\
font-size: 0.8rem;\
}\
\
td:first-child {\
font-size: 0.8rem;\
width: 35%%;\
}\
\
input[type='text'], input[type='number'], select {\
font-size: 0.9rem;\
padding: 0.65rem;\
}\
}\
.modal-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%%; height: 100%%; background: rgba(0,0,0,0.7); z-index: 1000; justify-content: center; align-items: center; }\
.modal-overlay.show { display: flex; }\
.modal-box { background: rgba(30, 30, 46, 0.98); border: 2px solid #f5576c; border-radius: 12px; padding: 1.5rem; max-width: 400px; text-align: center; box-shadow: 0 8px 32px rgba(245, 87, 108, 0.3); }\
.modal-box h3 { color: #f5576c; margin-bottom: 1rem; }\
.modal-box p { color: #e0e0e0; margin-bottom: 1.5rem; }\
.modal-box button { background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: #fff; border: none; border-radius: 8px; padding: 0.75rem 2rem; font-size: 1rem; cursor: pointer; }\
</style>\
<body>\
%s\
<div id='container'>\
<div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;'>\
<div style='display: flex; align-items: center;'>\
<a href='/' style='display: inline-block; margin-right: 1rem;'><img src='/favicon.png' alt='Home' style='width: 64px; height: 64px; border: none;'></a>\
<h1 style='margin: 0;'>Mappings</h1>\
</div>\
%s\
</div>\
\
<div class='section'>\
<h2>Connected Clients</h2>\
<table class='data-table'>\
<thead>\
<tr>\
<th>MAC Address</th>\
<th>IP Address</th>\
<th>Device Name</th>\
</tr>\
</thead>\
<tbody>\
%s\
</tbody>\
</table>\
</div>\
\
<div class='section'>\
<h2>DHCP Reservations</h2>\
<table class='data-table'>\
<thead>\
<tr>\
<th>MAC Address</th>\
<th>IP Address</th>\
<th>Name</th>\
<th>Action</th>\
</tr>\
</thead>\
<tbody>\
%s\
</tbody>\
</table>\
\
<h2>Add DHCP Reservation</h2>\
<form action='/mappings' method='GET'>\
<table>\
<tr>\
<td>MAC Address</td>\
<td><input type='text' name='dhcp_mac' placeholder='AA:BB:CC:DD:EE:FF'/></td>\
</tr>\
<tr>\
<td>IP Address</td>\
<td><input type='text' name='dhcp_ip' placeholder='192.168.4.100'/></td>\
</tr>\
<tr>\
<td>Name (optional)</td>\
<td><input type='text' name='dhcp_name' placeholder='My Device'/></td>\
</tr>\
<tr>\
<td></td>\
<td><input type='submit' name='dhcp_action' value='Add Reservation' class='ok-button'/></td>\
</tr>\
</table>\
</form>\
</div>\
\
<div class='section'>\
<h2>Port Forwarding</h2>\
<table class='data-table'>\
<thead>\
<tr>\
<th>Protocol</th>\
<th>Ext. Port</th>\
<th>Internal IP</th>\
<th>Int. Port</th>\
<th>Action</th>\
</tr>\
</thead>\
<tbody>\
%s\
</tbody>\
</table>\
\
<h2>Add Port Forwards</h2>\
<form action='/mappings' method='GET'>\
<table>\
<tr>\
<td>Protocol</td>\
<td>\
<select name='proto'>\
<option value='TCP'>TCP</option>\
<option value='UDP'>UDP</option>\
</select>\
</td>\
</tr>\
<tr>\
<td>External Port</td>\
<td><input type='number' name='ext_port' min='1' max='65535' placeholder='8080'/></td>\
</tr>\
<tr>\
<td>Internal IP</td>\
<td><input type='text' name='int_ip' placeholder='IP or device name'/></td>\
</tr>\
<tr>\
<td>Internal Port</td>\
<td><input type='number' name='int_port' min='1' max='65535' placeholder='80'/></td>\
</tr>\
<tr>\
<td></td>\
<td><input type='submit' name='port_action' value='Add Forward' class='ok-button'/></td>\
</tr>\
</table>\
</form>\
</div>\
<div style='margin-top: 2rem; text-align: center;'>\
<a href='/' style='padding: 0.75rem 2rem; background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: #fff; border: none; border-radius: 8px; text-decoration: none; font-size: 0.95rem; font-weight: 600; cursor: pointer; transition: all 0.3s; box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4); display: inline-block;'>🏠 Home</a>\
</div>\
</div>\
</body>\
</html>\
"

/* Firewall (ACL) Page */
#define FIREWALL_PAGE "<html>\
<head>\
<meta name='viewport' content='width=device-width, initial-scale=1, maximum-scale=1, user-scalable=0'>\
<meta charset='UTF-8'>\
<title>Firewall</title>\
<link rel='icon' href='favicon.png'>\
</head>\
<style>\
* { box-sizing: border-box; margin: 0; padding: 0; }\
body {\
font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;\
background: linear-gradient(135deg, #1a1a2e 0%%, #16213e 100%%);\
color: #e0e0e0; padding: 1rem; min-height: 100vh; line-height: 1.6;\
}\
h1 { font-size: 1.5rem; font-weight: 600; color: #00d9ff; margin-bottom: 1rem; text-shadow: 0 0 20px rgba(0, 217, 255, 0.3); }\
h2 { font-size: 1.1rem; font-weight: 500; color: #00d9ff; margin: 1.2rem 0 0.5rem 0; padding-bottom: 0.3rem; border-bottom: 1px solid rgba(0, 217, 255, 0.2); }\
h3 { font-size: 0.95rem; font-weight: 500; color: #f093fb; margin: 0.8rem 0 0.3rem 0; }\
#container { max-width: 900px; margin: 0 auto; padding: 1.5rem; background: rgba(30, 30, 46, 0.9); border-radius: 16px; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4); }\
.data-table { width: 100%%; border-collapse: collapse; margin: 0.5rem 0; background: rgba(22, 33, 62, 0.6); border-radius: 8px; overflow: hidden; border: 1px solid rgba(0, 217, 255, 0.1); font-size: 0.8rem; }\
.data-table thead { background: rgba(0, 217, 255, 0.1); }\
.data-table th { padding: 0.4rem 0.2rem; text-align: left; font-weight: 600; color: #00d9ff; font-size: 0.75rem; }\
.data-table td { padding: 0.4rem 0.2rem; border-bottom: 1px solid rgba(255, 255, 255, 0.05); font-size: 0.75rem; }\
.data-table tbody tr:last-child td { border-bottom: none; }\
.data-table tbody tr:hover { background: rgba(0, 217, 255, 0.05); }\
table.form-table { width: 100%%; border-collapse: collapse; }\
table.form-table td { padding: 0.3rem 0; vertical-align: top; }\
table.form-table td:first-child { color: #888; font-size: 0.8rem; padding-right: 0.5rem; width: 22%%; text-align: right; }\
input[type='text'], input[type='number'], select { width: 100%%; background: rgba(22, 33, 62, 0.6); border: 1px solid rgba(0, 217, 255, 0.2); border-radius: 6px; color: #e0e0e0; padding: 0.4rem; font-size: 0.85rem; }\
input:focus, select:focus { outline: none; border-color: #00d9ff; }\
.ok-button { background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: #fff; border: none; border-radius: 6px; padding: 0.5rem 1rem; font-size: 0.85rem; font-weight: 600; cursor: pointer; width: 100%%; margin-top: 0.25rem; }\
.red-button { background: linear-gradient(135deg, #f093fb 0%%, #f5576c 100%%); color: #fff; border: none; border-radius: 4px; padding: 0.2rem 0.4rem; font-size: 0.7rem; font-weight: 600; cursor: pointer; text-decoration: none; display: inline-block; }\
.orange-button { background: linear-gradient(135deg, #ff9a56 0%%, #ff6b35 100%%); color: #fff; border: none; border-radius: 4px; padding: 0.2rem 0.4rem; font-size: 0.7rem; font-weight: 600; cursor: pointer; text-decoration: none; display: inline-block; }\
.acl-section { margin-bottom: 1rem; padding: 0.8rem; background: rgba(22, 33, 62, 0.4); border-radius: 10px; border: 1px solid rgba(0, 217, 255, 0.1); }\
.stats { font-size: 0.75rem; color: #888; margin-bottom: 0.3rem; }\
.stats span { margin-right: 0.8rem; }\
.stats .allowed { color: #4caf50; }\
.stats .denied { color: #f44336; }\
@media (max-width: 768px) { body { padding: 0.5rem; } #container { padding: 1rem; } .data-table { font-size: 0.65rem; display: block; overflow-x: auto; } .data-table th, .data-table td { padding: 0.2rem 0.1rem; font-size: 0.65rem; } }\
.modal-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%%; height: 100%%; background: rgba(0,0,0,0.7); z-index: 1000; justify-content: center; align-items: center; }\
.modal-overlay.show { display: flex; }\
.modal-box { background: rgba(30, 30, 46, 0.98); border: 2px solid #f5576c; border-radius: 12px; padding: 1.5rem; max-width: 400px; text-align: center; box-shadow: 0 8px 32px rgba(245, 87, 108, 0.3); }\
.modal-box h3 { color: #f5576c; margin-bottom: 1rem; }\
.modal-box p { color: #e0e0e0; margin-bottom: 1.5rem; }\
.modal-box button { background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: #fff; border: none; border-radius: 6px; padding: 0.5rem 1.5rem; font-size: 0.9rem; font-weight: 600; cursor: pointer; }\
</style>\
<body>\
%s\
<div id='container'>\
<div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;'>\
<div style='display: flex; align-items: center;'>\
<a href='/' style='display: inline-block; margin-right: 1rem;'><img src='/favicon.png' alt='Home' style='width: 64px; height: 64px; border: none;'></a>\
<h1 style='margin: 0;'>Firewall</h1>\
</div>\
%s\
</div>\
<p style='color: #888; font-size: 0.8rem; margin-bottom: 0.8rem;'>Rules processed top-down. First match wins. No match = allow (permissive).</p>\
%s\
<h2>Add ACL Rule</h2>\
<form action='/firewall' method='GET'>\
<table class='form-table'>\
<tr><td>Direction</td><td><select name='acl_list'>\
<option value='0'>Internet to ESP (to_sta))</option>\
<option value='1'>ESP to Internet (from_sta))</option>\
<option value='2'>Cients to ESP (to_ap))</option>\
<option value='3'>ESP to Clients (from_ap)</option>\
</select></td></tr>\
<tr><td>Protocol</td><td><select name='proto'>\
<option value='0'>IP (Any)</option>\
<option value='6'>TCP</option>\
<option value='17'>UDP</option>\
<option value='1'>ICMP</option>\
</select></td></tr>\
<tr><td>Source IP</td><td><input type='text' name='src_ip' placeholder='any, IP/CIDR, or device name'/></td></tr>\
<tr><td>Source Port</td><td><input type='text' name='src_port' placeholder='* or port (TCP/UDP)'/></td></tr>\
<tr><td>Dest IP</td><td><input type='text' name='dst_ip' placeholder='any, IP/CIDR, or device name'/></td></tr>\
<tr><td>Dest Port</td><td><input type='text' name='dst_port' placeholder='* or port (TCP/UDP)'/></td></tr>\
<tr><td>Action</td><td><select name='action'>\
<option value='1'>Allow</option>\
<option value='0'>Deny</option>\
<option value='3'>Allow+Monitor</option>\
<option value='2'>Deny+Monitor</option>\
</select></td></tr>\
<tr><td></td><td><input type='submit' name='acl_action' value='Add Rule' class='ok-button'/></td></tr>\
</table>\
</form>\
<div style='margin-top: 1.5rem; text-align: center;'>\
<a href='/' style='padding: 0.6rem 1.5rem; background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: #fff; border: none; border-radius: 8px; text-decoration: none; font-size: 0.9rem; font-weight: 600;'>🏠 Home</a>\
</div>\
</div>\
</body>\
</html>\
"
