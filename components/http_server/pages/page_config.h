/* Configuration page templates */
#include "router_config.h"
#include "wifi_config.h"

/* Configuration Page - WiFi settings and MAC addresses */
/* Config Page - Chunked for streaming */
#define CONFIG_CHUNK_HEAD "<html>\
<head>\
<meta name='viewport' content='width=device-width, initial-scale=1, maximum-scale=1, user-scalable=0'>\
<meta charset='UTF-8'>\
<title>Configuration</title>\
<link rel='icon' href='favicon.png'>\
</head>\
<style>\
* { box-sizing: border-box; margin: 0; padding: 0; }\
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: #e0e0e0; padding: 1rem; min-height: 100vh; line-height: 1.6; }\
h1 { font-size: 1.5rem; font-weight: 600; color: #00d9ff; margin-bottom: 1rem; text-shadow: 0 0 20px rgba(0, 217, 255, 0.3); }\
h2 { font-size: 1.15rem; font-weight: 500; color: #00d9ff; margin: 1.5rem 0 0.75rem 0; padding-bottom: 0.5rem; border-bottom: 1px solid rgba(0, 217, 255, 0.2); }\
#container { max-width: 500px; margin: 0 auto; padding: 1.5rem; background: rgba(30, 30, 46, 0.9); border-radius: 16px; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4); backdrop-filter: blur(10px); }\
form { margin-bottom: 1.5rem; }\
table { width: 100%; border-collapse: collapse; }\
td { padding: 0.5rem 0; vertical-align: top; }\
td:first-child { color: #888; font-size: 0.9rem; padding-right: 0.75rem; width: 35%; text-align: right; }\
input[type='text'], input[type='password'], input[type='number'] { width: 100%; background: rgba(22, 33, 62, 0.6); border: 1px solid rgba(0, 217, 255, 0.2); border-radius: 8px; color: #e0e0e0; padding: 0.75rem; font-size: 0.95rem; }\
input[type='text']:focus, input[type='password']:focus, input[type='number']:focus, select:focus { outline: none; border-color: #00d9ff; box-shadow: 0 0 0 3px rgba(0, 217, 255, 0.1); background: rgba(22, 33, 62, 0.8); }\
input::placeholder { color: #666; }\
select { width: 100%; background: rgba(22, 33, 62, 0.6); border: 1px solid rgba(0, 217, 255, 0.2); border-radius: 8px; color: #e0e0e0; padding: 0.75rem; font-size: 0.95rem; cursor: pointer; -webkit-appearance: none; -moz-appearance: none; appearance: none; background-image: url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8'%3E%3Cpath d='M1 1l5 5 5-5' stroke='%2300d9ff' stroke-width='1.5' fill='none'/%3E%3C/svg%3E\"); background-repeat: no-repeat; background-position: right 0.75rem center; padding-right: 2rem; }\
select option { background: #16213e; color: #e0e0e0; }\
input[type='checkbox'], input[type='radio'] { -webkit-appearance: none; -moz-appearance: none; appearance: none; width: 18px; height: 18px; border: 2px solid rgba(0, 217, 255, 0.3); border-radius: 4px; background: rgba(22, 33, 62, 0.6); cursor: pointer; vertical-align: middle; position: relative; flex-shrink: 0; }\
input[type='radio'] { border-radius: 50%; }\
input[type='checkbox']:checked, input[type='radio']:checked { background: #00d9ff; border-color: #00d9ff; }\
input[type='checkbox']:checked::after { content: ''; position: absolute; left: 4px; top: 1px; width: 6px; height: 10px; border: solid #1a1a2e; border-width: 0 2px 2px 0; transform: rotate(45deg); }\
input[type='radio']:checked::after { content: ''; position: absolute; left: 3px; top: 3px; width: 8px; height: 8px; border-radius: 50%; background: #1a1a2e; }\
input[type='checkbox']:focus, input[type='radio']:focus { outline: none; border-color: #00d9ff; box-shadow: 0 0 0 3px rgba(0, 217, 255, 0.1); }\
.ok-button, .red-button { border: none; border-radius: 8px; padding: 0.75rem 1.5rem; font-size: 0.95rem; font-weight: 600; cursor: pointer; width: 100%; margin-top: 0.5rem; }\
.ok-button { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #fff; box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4); }\
.red-button { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: #fff; box-shadow: 0 4px 15px rgba(245, 87, 108, 0.4); }\
small { display: block; color: #888; font-size: 0.85rem; margin-top: 0.5rem; line-height: 1.4; }\
@media (max-width: 600px) { body { padding: 0.5rem; } #container { padding: 1rem; } h1 { font-size: 1.25rem; } h2 { font-size: 1rem; } td:first-child { font-size: 0.8rem; width: 40%; } input[type='text'], input[type='password'], input[type='number'], select { font-size: 0.9rem; padding: 0.65rem; } select { padding-right: 1.75rem; } .ok-button, .red-button { font-size: 0.9rem; padding: 0.65rem 1.25rem; } }\
</style>\
<body>\
<div id='container'>\
<div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;'>\
<div style='display: flex; align-items: center;'>\
<a href='/' style='display: inline-block; margin-right: 1rem;'><img src='/favicon.png' alt='Home' style='width: 64px; height: 64px; border: none;'></a>\
<h1 style='margin: 0;'>Configuration</h1>\
</div>"

/* After logout section */
#define CONFIG_CHUNK_SCRIPT "\
</div>\
<script>\
var qs = window.location.search.substr(1);\
var formSubmitted = qs.indexOf('ap_ssid=') !== -1 || (qs.indexOf('ssid=') !== -1 && qs.indexOf('password=') !== -1) || qs.indexOf('staticip=') !== -1 || qs.indexOf('reset=') !== -1 || qs.indexOf('disable_interface=') !== -1;\
if (formSubmitted) {\
document.getElementById('container').style.display = 'none';\
document.body.innerHTML ='<div id=\"container\"><h1>Configuration</h1><p style=\"text-align:center; margin: 2rem 0; color: #00d9ff;\">Settings saved! Rebooting...</p></div>';\
setTimeout(\"location.href = '/'\", 10000);\
}\
</script>"

/* AP Settings section - uses %s for: ap_ssid, ap_ip, ap_dns, ap_mac, open_checked, hidden_checked */
/* ETH_UPLINK builds add an extra %d for ap_channel */
#if CONFIG_ETH_UPLINK
#define CONFIG_CHUNK_AP_CHANNEL_ROW \
"<tr><td>Channel</td><td><input type='number' name='ap_channel' min='0' max='13' value='%d' style='width:4em'/> <span style='color:#888;font-size:0.85rem;'>(0 = auto)</span></td></tr>"
#else
#define CONFIG_CHUNK_AP_CHANNEL_ROW ""
#endif
#define CONFIG_CHUNK_AP "\
<h2>Access Point Settings</h2>\
<form action='' method='GET'>\
<table>\
<tr><td>SSID</td><td><input type='text' name='ap_ssid' value='%s' placeholder='Network name'/></td></tr>\
<tr><td>Password</td><td><input type='text' id='ap_pw' name='ap_password' placeholder='unchanged' oninput=\"document.getElementById('ap_op').checked=false;\"/></td></tr>\
<tr><td>AP IP Address</td><td><input type='text' name='ap_ip_addr' value='%s' placeholder='192.168.4.1'/></td></tr>\
<tr><td>DNS Server</td><td><input type='text' name='ap_dns' value='%s' placeholder='empty = use upstream DNS'/></td></tr>\
<tr><td>MAC Address</td><td><input type='text' name='ap_mac' value='%s' placeholder='AA:BB:CC:DD:EE:FF'/></td></tr>\
" CONFIG_CHUNK_AP_CHANNEL_ROW "\
<tr><td>Security</td><td><select name='ap_auth'><option value='0' %s>WPA2/WPA3</option><option value='1' %s>WPA2 only</option><option value='2' %s>WPA3 only</option></select></td></tr>\
<tr><td>Options</td><td><input type='checkbox' id='ap_op' name='ap_open' value='1' %s onchange=\"if(this.checked)document.getElementById('ap_pw').value='';\"> <span style='color:#888;font-size:0.85rem;'>Open (no password)</span> &nbsp; <input type='checkbox' name='ap_hidden' value='1' %s> <span style='color:#888;font-size:0.85rem;'>Hidden SSID</span></td></tr>\
<tr><td></td><td><input type='submit' value='Save &amp; Reboot' class='ok-button'/></td></tr>\
</table>\
</form>"

#if !CONFIG_ETH_UPLINK
/* STA band preference row (5 GHz capable targets only) */
/* Uses %s x3 for: auto_selected, 2.4_selected, 5_selected */
#if WIFI_HAS_5GHZ
#define CONFIG_CHUNK_STA_BAND_ROW \
"<tr><td>Band</td><td><select name='sta_band'>\
<option value='0' %s>Auto (strongest signal)</option>\
<option value='1' %s>2.4 GHz only</option>\
<option value='2' %s>5 GHz only</option>\
</select></td></tr>"
#else
#define CONFIG_CHUNK_STA_BAND_ROW ""
#endif

/* STA Settings section - uses %s for: ssid, ent_username, ent_identity,
   eap_method selected x4, ttls_phase2 selected x4, cert_bundle checked, no_time_chk checked,
   [if WIFI_HAS_5GHZ: band_auto_sel, band_2g_sel, band_5g_sel,]
   sta_mac */
#define CONFIG_CHUNK_STA "\
<h2>Station Settings (Uplink)</h2>\
<form action='' method='GET'>\
<table>\
<tr><td>SSID</td><td><input type='text' name='ssid' value='%s' placeholder='Uplink network'/></td></tr>\
<tr><td>Password</td><td><input type='text' name='password' placeholder='unchanged'/></td></tr>\
" CONFIG_CHUNK_STA_BAND_ROW "\
<tr><td colspan='2' style='padding-top: 1rem; color: #888; font-size: 0.85rem;'>WPA2 Enterprise (optional)</td></tr>\
<tr><td>Username</td><td><input type='text' name='ent_username' value='%s' placeholder='Enterprise username'/></td></tr>\
<tr><td>Identity</td><td><input type='text' name='ent_identity' value='%s' placeholder='Optional (defaults to username)'/></td></tr>\
<tr><td>EAP Method</td><td><select name='eap_method'>\
<option value='0' %s>Auto</option>\
<option value='1' %s>PEAP</option>\
<option value='2' %s>TTLS</option>\
<option value='3' %s>TLS</option>\
</select></td></tr>\
<tr><td>TTLS Phase 2</td><td><select name='ttls_phase2'>\
<option value='0' %s>MSCHAPv2</option>\
<option value='1' %s>MSCHAP</option>\
<option value='2' %s>PAP</option>\
<option value='3' %s>CHAP</option>\
</select></td></tr>\
<tr><td>Options</td><td>\
<input type='checkbox' name='cert_bundle' value='1' %s> <span style='color:#888;font-size:0.85rem;'>Use CA cert bundle</span><br>\
<input type='checkbox' name='no_time_chk' value='1' %s> <span style='color:#888;font-size:0.85rem;'>Skip cert time check</span>\
</td></tr>\
<tr><td>MAC Address</td><td><input type='text' name='sta_mac' value='%s' placeholder='AA:BB:CC:DD:EE:FF'/></td></tr>\
<tr><td></td><td><input type='submit' value='Save &amp; Reboot' class='ok-button'/></td></tr>\
</table>\
</form>"
#endif

/* Static IP section - uses %s for: static_ip, subnet_mask, gateway */
#define CONFIG_CHUNK_STATIC "\
<h2>Static IP Settings</h2>\
<form action='' method='GET'>\
<table>\
<tr><td>Static IP</td><td><input type='text' name='staticip' value='%s' placeholder='192.168.1.100'/></td></tr>\
<tr><td>Subnet Mask</td><td><input type='text' name='subnetmask' value='%s' placeholder='255.255.255.0'/></td></tr>\
<tr><td>Gateway</td><td><input type='text' name='gateway' value='%s' placeholder='192.168.1.1'/></td></tr>\
<tr><td></td><td><input type='submit' value='Save &amp; Reboot' class='ok-button'/></td></tr>\
</table>\
<small>Leave empty for DHCP</small>\
</form>"

/* Remote Console section - uses: rc_en_chk, rc_dis_chk, rc_color, rc_status, rc_kick, rc_port, rc_ap_chk, rc_sta_chk, rc_vpn_chk, rc_timeout */
#define CONFIG_CHUNK_RC "\
<h2>Remote Console</h2>\
<form action='' method='GET'>\
<input type='hidden' name='rc_save' value='1'/>\
<table>\
<tr><td>Service</td><td>\
<label style='margin-right: 1rem;'><input type='radio' name='rc_enabled' value='1' %s> Enabled</label>\
<label><input type='radio' name='rc_enabled' value='0' %s> Disabled</label>\
</td></tr>\
<tr><td>Status</td><td><strong style='color: %s;'>%s</strong>%s</td></tr>\
<tr><td>Port</td><td><input type='number' name='rc_port' value='%d' min='1' max='65535' style='width: 100px;'/></td></tr>\
<tr><td>Bind Interfaces</td><td>\
<label style='margin-right: 0.8rem;'><input type='checkbox' name='rc_bind_ap' value='1' %s> AP</label>\
<label style='margin-right: 0.8rem;'><input type='checkbox' name='rc_bind_sta' value='1' %s> STA</label>\
<label><input type='checkbox' name='rc_bind_vpn' value='1' %s> VPN</label>\
</td></tr>\
<tr><td>Idle Timeout</td><td><input type='number' name='rc_timeout' value='%lu' min='0' max='86400' style='width: 100px;'/> sec (0 = no)</td></tr>\
<tr><td></td><td><input type='submit' value='Save' class='ok-button'/></td></tr>\
</table>\
</form>"

/* PCAP section - uses: pcap_off/acl/promisc_sel, pcap_color, pcap_status, captured, dropped, snaplen, sta_ip */
#define CONFIG_CHUNK_PCAP "\
<h2>PCAP Packet Capture</h2>\
<form action='' method='GET'>\
<input type='hidden' name='pcap_save' value='1'/>\
<table>\
<tr><td>Mode</td><td>\
<select name='pcap_mode'>\
<option value='off' %s>Off</option>\
<option value='acl' %s>ACL Monitor</option>\
<option value='promisc' %s>Promiscuous</option>\
</select>\
</td></tr>\
<tr><td>Client</td><td><strong style='color: %s;'>%s</strong></td></tr>\
<tr><td>Stats</td><td>%lu captured, %lu dropped</td></tr>\
<tr><td>Snaplen</td><td><input type='text' name='pcap_snaplen' value='%d' placeholder='64-1600'/></td></tr>\
<tr><td></td><td><input type='submit' value='Save' class='ok-button'/></td></tr>\
</table>\
<small>Connect using: nc %s 19000 | wireshark -k -i -</small>\
</form>"

/* Device management and footer */
#define CONFIG_CHUNK_TAIL "\
<h2>Device Management</h2>\
<div id='mainContent'>\
<h3 style='font-size:1rem;color:#aaa;margin:1rem 0 0.5rem;'>Firmware Update (OTA)</h3>"

/* OTA info (running partition, version) is streamed dynamically here */
#define CONFIG_CHUNK_TAIL2 "\
<table>\
<tr><td>Upload</td><td>\
<label style='display:inline-block;padding:0.6rem 1rem;background:rgba(22,33,62,0.6);border:1px solid rgba(0,217,255,0.2);border-radius:8px;color:#e0e0e0;font-size:0.9rem;cursor:pointer;transition:all 0.3s;margin-bottom:0.5rem;'>\
<input type='file' id='otaFile' accept='.bin' style='display:none;'/>\
<span id='otaFileName'>Choose .bin file...</span>\
</label><br/>\
<button type='button' onclick='uploadOTA()' class='ok-button'>Upload Firmware</button>\
<div id='otaProgress' style='margin-top:0.5rem;'>\
<div id='otaBar' style='display:none;height:6px;background:rgba(0,217,255,0.2);border-radius:3px;overflow:hidden;'>\
<div id='otaBarFill' style='height:100%;width:0;background:#00d9ff;transition:width 0.3s;'></div>\
</div>\
</div>\
<div id='otaStatus' style='margin-top:0.5rem;font-size:0.9rem;'></div>\
</td></tr>\
</table>\
<h3 style='font-size:1rem;color:#aaa;margin:1.5rem 0 0.5rem;'>Config Backup / Restore</h3>\
<table>\
<tr><td>Export</td><td><a href='/api/config-export' class='ok-button' style='display:inline-block;text-align:center;text-decoration:none;'>Write Config</a></td></tr>\
<tr><td>Import</td><td>\
<label style='display:inline-block;padding:0.6rem 1rem;background:rgba(22,33,62,0.6);border:1px solid rgba(0,217,255,0.2);border-radius:8px;color:#e0e0e0;font-size:0.9rem;cursor:pointer;transition:all 0.3s;margin-bottom:0.5rem;'>\
<input type='file' id='cfgFile' accept='.json' style='display:none;'/>\
<span id='cfgFileName'>Choose file...</span>\
</label><br/>\
<button type='button' onclick='uploadConfig()' class='ok-button'>Read Config</button>\
<div id='importStatus' style='margin-top:0.5rem;font-size:0.9rem;'></div>\
</td></tr>\
</table>\
<h3 style='font-size:1rem;color:#aaa;margin:1.5rem 0 0.5rem;'>Reboot</h3>\
<form action='' method='GET'>\
<table>\
<tr><td>Device</td><td><input type='submit' name='reset' value='Reboot Now' class='red-button'/></td></tr>\
</table>\
</form>\
</div>\
<div id='rebootScreen' style='display:none;text-align:center;padding:2rem 0;'>\
<h2 style='color:#4caf50;margin-bottom:1rem;' id='rebootTitle'>Success</h2>\
<p style='font-size:1.1rem;margin-bottom:0.5rem;' id='rebootMsg'>The device is rebooting...</p>\
<p style='font-size:1.5rem;font-weight:bold;color:#00d9ff;' id='countdown'></p>\
<p style='color:#888;font-size:0.9rem;'>Redirecting to home page...</p>\
</div>\
<script>\
document.getElementById('otaFile').addEventListener('change',function(){document.getElementById('otaFileName').textContent=this.files[0]?this.files[0].name:'Choose .bin file...';});\
function uploadOTA(){\
var f=document.getElementById('otaFile').files[0];\
if(!f){document.getElementById('otaStatus').textContent='Select a firmware file first.';return;}\
if(!f.name.endsWith('.bin')){document.getElementById('otaStatus').innerHTML='<span style=\"color:#ff5252;\">Please select a .bin file</span>';return;}\
document.getElementById('otaStatus').textContent='Uploading...';\
document.getElementById('otaBar').style.display='block';\
var xhr=new XMLHttpRequest();\
xhr.open('POST','/api/ota-upload',true);\
xhr.upload.onprogress=function(e){if(e.lengthComputable){var pct=Math.round(e.loaded/e.total*100);document.getElementById('otaBarFill').style.width=pct+'%';document.getElementById('otaStatus').textContent='Uploading... '+pct+'%';}};\
xhr.onload=function(){\
try{var d=JSON.parse(xhr.responseText);\
if(d.ok){\
document.getElementById('mainContent').style.display='none';\
document.getElementById('rebootScreen').style.display='block';\
document.getElementById('rebootTitle').textContent='Firmware Updated';\
document.getElementById('rebootMsg').textContent='The device is rebooting with new firmware.';\
var c=10;var el=document.getElementById('countdown');\
var t=setInterval(function(){c--;el.textContent=c;if(c<=0){clearInterval(t);window.location.href='/';}},1000);\
}else{\
document.getElementById('otaBarFill').style.width='0';document.getElementById('otaBar').style.display='none';\
document.getElementById('otaStatus').innerHTML='<span style=\"color:#ff5252;\">'+d.msg+'</span>';\
}}catch(e){document.getElementById('otaStatus').innerHTML='<span style=\"color:#ff5252;\">Upload failed</span>';}\
};\
xhr.onerror=function(){document.getElementById('otaStatus').innerHTML='<span style=\"color:#ff5252;\">Connection error</span>';};\
xhr.send(f);\
}\
document.getElementById('cfgFile').addEventListener('change',function(){document.getElementById('cfgFileName').textContent=this.files[0]?this.files[0].name:'Choose file...';});\
function uploadConfig(){\
var f=document.getElementById('cfgFile').files[0];\
if(!f){document.getElementById('importStatus').textContent='Select a file first.';return;}\
var r=new FileReader();\
r.onload=function(){\
document.getElementById('importStatus').textContent='Uploading...';\
fetch('/api/config-import',{method:'POST',body:r.result,headers:{'Content-Type':'application/json'}})\
.then(function(res){return res.json();})\
.then(function(d){\
if(d.ok){\
document.getElementById('mainContent').style.display='none';\
document.getElementById('rebootScreen').style.display='block';\
document.getElementById('rebootTitle').textContent='Config Imported';\
document.getElementById('rebootMsg').textContent='The device is rebooting to apply the new configuration.';\
var c=5;var el=document.getElementById('countdown');\
var t=setInterval(function(){c--;el.textContent=c;if(c<=0){clearInterval(t);window.location.href='/';}},1000);\
}else{\
document.getElementById('importStatus').innerHTML='<span style=\"color:#ff5252;\">'+d.msg+'</span>';\
}\
});\
};\
r.readAsText(f);\
}\
</script>\
<div style='margin-top: 2rem; padding: 1rem; background: #fff3cd; border: 2px solid #ff9800; border-radius: 8px;'>\
<h2 style='color: #ff6b00; margin-bottom: 0.5rem;'>⚠ Danger Zone</h2>\
<p style='margin-bottom: 1rem; color: #666; font-size: 0.9rem;'>This will disable the web interface completely. You can only re-enable it via the console using the 'web_ui enable' command.</p>\
<form action='' method='GET'>\
<table>\
<tr><td style='color: #d32f2f; font-weight: bold;'>Disable Interface</td>\
<td><input type='submit' name='disable_interface' value='Disable' class='red-button' onclick='return confirm(\"Are you sure? The web interface will be disabled and can only be re-enabled via the console.\");'/></td></tr>\
</table>\
</form>\
</div>\
<div style='margin-top: 2rem; text-align: center;'>\
<a href='/' style='padding: 0.75rem 2rem; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #fff; border: none; border-radius: 8px; text-decoration: none; font-size: 0.95rem; font-weight: 600;'>🏠 Home</a>\
</div>\
</div>\
</body>\
</html>"

