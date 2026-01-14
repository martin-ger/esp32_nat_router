#define CONFIG_PAGE "<html>\
<head></head>\
<meta name='viewport' content='width=device-width, initial-scale=1'>\
<style>\
body {\
font-family: apercu-pro, -apple-system, system-ui, BlinkMacSystemFont, 'Helvetica Neue', sans-serif;\
padding: 1em;\
line-height: 2em;\
font-weight: 100;\
}\
\
td {\
font-weight: 100;\
min-height: 24px;\
}\
\
td:first-child { \
text-align: right;\
min-width: 100px;\
padding-right: 10px;\
}\
\
h1 {\
font-size: 1.5em;\
font-weight: 200;\
}\
\
h2 {\
font-size: 1.2em;\
font-weight: 200;\
margin-left: 5px;\
}\
\
input {\
border: 1px solid rgb(196, 196, 196);\
color: rgb(76, 76, 76);\
width: 240px;\
border-radius: 3px;\
height: 40px;\
margin: 3px 0px;\
padding: 0px 14px;\
}\
\
input:focus {\
border:1px solid black;\
outline: none !important;\
box-shadow: 0 0 10px #719ECE;\
}\
\
#config {\
width:400px; \
margin:0 auto;\
}\
\
.ok-button {\
background-color: #0078e7;\
color: #fff;\
}\
\
.red-button {\
background-color: #e72e00;\
color: #fff;\
}\
</style>\
<body>\
<div id='config'>\
<h1>ESP32 NAT Router Config</h1>\
<div style='text-align: right; margin-bottom: 10px;'><a href='/advanced' style='color: #0078e7; text-decoration: none; font-size: 0.9em;'>Advanced Settings &rarr;</a></div>\
<script>\
if (window.location.search.substr(1) != '')\
{\
document.getElementById('config').display = 'none';\
document.body.innerHTML ='<h1>ESP32 NAT Router Config</h1>The new settings have been sent to the device.<br/>The page will refresh soon automatically...';\
setTimeout(\"location.href = '/'\",10000);\
}\
</script>\
<h2>AP Settings (the new network)</h2>\
<form action='' method='GET'>\
<table>\
<tr>\
<td>SSID</td>\
<td><input type='text' name='ap_ssid' value='%s' placeholder='SSID of the new network'/></td>\
</tr>\
<tr>\
<td>Password</td>\
<td><input type='text' name='ap_password' value='%s' placeholder='Password of the new network'/></td>\
</tr>\
<tr>\
<td></td>\
<td><input type='submit' value='Set' class='ok-button'/></td>\
</tr>\
</table>\
<small>\
<i>Password </i>less than 8 chars = open<br />\
</small>\
</form>\
\
<h2>STA Settings (uplink WiFi network)</h2>\
<form action='' method='GET'>\
<table>\
<tr>\
<td>SSID</td>\
<td><input type='text' name='ssid' value='%s' placeholder='SSID of existing network'/></td>\
</tr>\
<tr>\
<td>Password</td>\
<td><input type='text' name='password' value='%s' placeholder='Password of existing network'/></td>\
</tr>\
<tr>\
<td colspan='2'>WPA2 Enterprise settings. Leave blank for regular</td>\
</tr>\
<tr>\
<td>Enterprise username</td>\
<td><input type='text' name='ent_username' value='%s' placeholder='WPA2 Enterprise username'/></td>\
</tr>\
<tr>\
<td>Enterprise identity</td>\
<td><input type='text' name='ent_identity' value='%s' placeholder='WPA2 Enterprise identity'/></td>\
</tr>\
<tr>\
<td></td>\
<td><input type='submit' value='Connect' class='ok-button'/></td>\
</tr>\
\
</table>\
</form>\
\
<h2>STA Static IP Settings</h2>\
<form action='' method='GET'>\
<table>\
<tr>\
<td>Static IP</td>\
<td><input type='text' name='staticip' value='%s'/></td>\
</tr>\
<tr>\
<td>Subnet Mask</td>\
<td><input type='text' name='subnetmask' value='%s'/></td>\
</tr>\
<tr>\
<td>Gateway</td>\
<td><input type='text' name='gateway' value='%s'/></td>\
</tr>\
<tr>\
<td></td>\
<td><input type='submit' value='Connect' class='ok-button'/></td>\
</tr>\
\
</table>\
<small>\
<i>Leave it in blank if you want your ESP32 to get an IP using DHCP</i>\
</small>\
</form>\
\
<h2>Device Management</h2>\
<form action='' method='GET'>\
<table>\
<tr>\
<td>Device</td>\
<td><input type='submit' name='reset' value='Reboot' class='red-button'/></td>\
</tr>\
</table>\
</form>\
</div>\
</body>\
</html>\
"

#define LOCK_PAGE "<html>\
<head></head>\
<meta name='viewport' content='width=device-width, initial-scale=1'>\
<style>\
body {\
font-family: apercu-pro, -apple-system, system-ui, BlinkMacSystemFont, 'Helvetica Neue', sans-serif;\
padding: 1em;\
line-height: 2em;\
font-weight: 100;\
}\
\
td {\
font-weight: 100;\
min-height: 24px;\
}\
\
td:first-child { \
text-align: right;\
min-width: 100px;\
padding-right: 10px;\
}\
\
h1 {\
font-size: 1.5em;\
font-weight: 200;\
}\
\
h2 {\
font-size: 1.2em;\
font-weight: 200;\
margin-left: 5px;\
}\
\
input {\
border: 1px solid rgb(196, 196, 196);\
color: rgb(76, 76, 76);\
width: 240px;\
border-radius: 3px;\
height: 40px;\
margin: 3px 0px;\
padding: 0px 14px;\
}\
\
input:focus {\
border:1px solid black;\
outline: none !important;\
box-shadow: 0 0 10px #719ECE;\
}\
\
#config {\
width:400px; \
margin:0 auto;\
}\
\
.ok-button {\
background-color: #0078e7;\
color: #fff;\
}\
\
.red-button {\
background-color: #e72e00;\
color: #fff;\
}\
</style>\
<body>\
<div id='config'>\
<h1>ESP32 NAT Router Config</h1>\
<script>\
if (window.location.search.substr(1) != '')\
{\
document.getElementById('config').display = 'none';\
document.body.innerHTML ='<h1>ESP32 NAT Router Config</h1>The new settings have been sent to the device.<br/>The page will refresh soon automatically...';\
setTimeout(\"location.href = '/'\",1000);\
}\
</script>\
<h2>Config Locked</h2>\
<form autocomplete='off' action='' method='GET'>\
<table>\
<tr>\
<td>Password:</td>\
<td><input type='password' name='unlock_password'/></td>\
</tr>\
<tr>\
<td></td>\
<td><input type='submit' value='Unlock' class='red-button'/></td>\
</tr>\
\
</table>\
<small>\
<i>Default: STA password to unlock<br />\
</small>\
</form>\
</div>\
</body>\
</html>\
"

#define ADVANCED_PAGE "<html>\
<head></head>\
<meta name='viewport' content='width=device-width, initial-scale=1'>\
<style>\
body {\
font-family: apercu-pro, -apple-system, system-ui, BlinkMacSystemFont, 'Helvetica Neue', sans-serif;\
padding: 1em;\
line-height: 2em;\
font-weight: 100;\
}\
\
td {\
font-weight: 100;\
min-height: 24px;\
padding: 5px 8px;\
}\
\
td:first-child { \
text-align: right;\
min-width: 100px;\
padding-right: 10px;\
}\
\
h1 {\
font-size: 1.5em;\
font-weight: 200;\
}\
\
h2 {\
font-size: 1.2em;\
font-weight: 200;\
margin-left: 5px;\
}\
\
input, select {\
border: 1px solid rgb(196, 196, 196);\
color: rgb(76, 76, 76);\
width: 240px;\
border-radius: 3px;\
height: 40px;\
margin: 3px 0px;\
padding: 0px 14px;\
}\
\
input:focus {\
border:1px solid black;\
outline: none !important;\
box-shadow: 0 0 10px #719ECE;\
}\
\
#config {\
width:700px; \
margin:0 auto;\
}\
\
.ok-button {\
background-color: #0078e7;\
color: #fff;\
}\
\
.red-button {\
background-color: #e72e00;\
color: #fff;\
}\
\
.small-button {\
width: 60px;\
height: 30px;\
font-size: 0.9em;\
padding: 0px 10px;\
}\
\
.status-table {\
background: #f5f5f5;\
border-radius: 5px;\
padding: 10px;\
margin: 10px 0;\
}\
\
.portmap-table {\
width: 100%%;\
border-collapse: collapse;\
margin: 10px 0;\
}\
\
.portmap-table th {\
background: #e0e0e0;\
padding: 8px;\
text-align: left;\
}\
\
.portmap-table td {\
border-bottom: 1px solid #e0e0e0;\
padding: 8px;\
text-align: left;\
}\
\
.nav-link {\
color: #0078e7;\
text-decoration: none;\
font-size: 0.9em;\
}\
\
.nav-link:hover {\
text-decoration: underline;\
}\
</style>\
<body>\
<div id='config'>\
<a href='/' class='nav-link'>&larr; Back to Main Config</a>\
<h1>ESP32 NAT Router - Advanced</h1>\
<script>\
if (window.location.search.indexOf('success=1') > -1) {\
alert('Settings saved successfully!');\
window.history.replaceState({}, document.title, window.location.pathname);\
}\
</script>\
\
<h2>System Status</h2>\
<div class='status-table'>\
<table>\
<tr>\
<td>Connection Status:</td>\
<td><strong>%s</strong></td>\
</tr>\
<tr>\
<td>STA IP Address:</td>\
<td>%s</td>\
</tr>\
<tr>\
<td>AP IP Address:</td>\
<td>%s</td>\
</tr>\
<tr>\
<td>Connected Clients:</td>\
<td>%d</td>\
</tr>\
<tr>\
<td>Free Heap:</td>\
<td>%d KB</td>\
</tr>\
</table>\
</div>\
\
<h2>Port Forwarding</h2>\
<table class='portmap-table'>\
<thead>\
<tr>\
<th>Protocol</th>\
<th>External Port</th>\
<th>Internal IP</th>\
<th>Internal Port</th>\
<th>Action</th>\
</tr>\
</thead>\
<tbody>\
%s\
</tbody>\
</table>\
\
<h2>Add Port Mapping</h2>\
<form action='/advanced' method='GET'>\
<table>\
<tr>\
<td>Protocol</td>\
<td>\
<select name='proto' style='width:100px;'>\
<option value='TCP'>TCP</option>\
<option value='UDP'>UDP</option>\
</select>\
</td>\
</tr>\
<tr>\
<td>External Port</td>\
<td><input type='number' name='ext_port' min='1' max='65535' placeholder='e.g. 8080' style='width:100px;'/></td>\
</tr>\
<tr>\
<td>Internal IP</td>\
<td><input type='text' name='int_ip' placeholder='e.g. 192.168.4.2' style='width:150px;'/></td>\
</tr>\
<tr>\
<td>Internal Port</td>\
<td><input type='number' name='int_port' min='1' max='65535' placeholder='e.g. 80' style='width:100px;'/></td>\
</tr>\
<tr>\
<td></td>\
<td><input type='submit' name='action' value='Add Mapping' class='ok-button'/></td>\
</tr>\
</table>\
</form>\
\
</div>\
</body>\
</html>\
"
