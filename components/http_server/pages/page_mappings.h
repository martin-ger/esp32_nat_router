/* Mappings page templates */
#include "router_config.h"

/* Mappings Page (DHCP Reservations + Port Forwarding) */
/* Mappings Page - Chunked for streaming */
#define MAPPINGS_CHUNK_HEAD "<html>\
<head>\
<meta name='viewport' content='width=device-width, initial-scale=1, maximum-scale=1, user-scalable=0'>\
<meta charset='UTF-8'>\
<title>Mappings</title>\
<link rel='icon' href='favicon.png'>\
</head>\
<style>\
* { box-sizing: border-box; margin: 0; padding: 0; }\
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: #e0e0e0; padding: 1rem; min-height: 100vh; line-height: 1.6; }\
h1 { font-size: 1.5rem; font-weight: 600; color: #00d9ff; margin-bottom: 1rem; text-shadow: 0 0 20px rgba(0, 217, 255, 0.3); }\
h2 { font-size: 1.15rem; font-weight: 500; color: #00d9ff; margin: 1.5rem 0 0.75rem 0; padding-bottom: 0.5rem; border-bottom: 1px solid rgba(0, 217, 255, 0.2); }\
#container { max-width: 800px; margin: 0 auto; padding: 1.5rem; background: rgba(30, 30, 46, 0.9); border-radius: 16px; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4); backdrop-filter: blur(10px); }\
.nav-link { color: #00d9ff; text-decoration: none; font-size: 0.9rem; display: inline-block; margin-bottom: 1rem; transition: all 0.2s; }\
.nav-link:hover { color: #33e0ff; transform: translateX(-3px); }\
.data-table { width: 100%; border-collapse: collapse; margin: 1rem 0; background: rgba(22, 33, 62, 0.6); border-radius: 12px; overflow: hidden; border: 1px solid rgba(0, 217, 255, 0.1); }\
.data-table thead { background: rgba(0, 217, 255, 0.1); }\
.data-table th { padding: 0.75rem 0.5rem; text-align: left; font-weight: 600; color: #00d9ff; font-size: 0.9rem; }\
.data-table td { padding: 0.75rem 0.5rem; border-bottom: 1px solid rgba(255, 255, 255, 0.05); font-size: 0.9rem; }\
.data-table td:first-child { color: #e0e0e0; text-align: left; width: auto; }\
.data-table tbody tr:last-child td { border-bottom: none; }\
.data-table tbody tr:hover { background: rgba(0, 217, 255, 0.05); }\
table { width: 100%; border-collapse: collapse; }\
td { padding: 0.5rem 0; vertical-align: top; }\
td:first-child { color: #888; font-size: 0.9rem; padding-right: 0.75rem; width: 30%; text-align: right; }\
input[type='text'], input[type='number'], select { width: 100%; background: rgba(22, 33, 62, 0.6); border: 1px solid rgba(0, 217, 255, 0.2); border-radius: 8px; color: #e0e0e0; padding: 0.75rem; font-size: 0.95rem; transition: all 0.3s; }\
input:focus, select:focus { outline: none; border-color: #00d9ff; box-shadow: 0 0 0 3px rgba(0, 217, 255, 0.1); background: rgba(22, 33, 62, 0.8); }\
input::placeholder { color: #666; }\
select { cursor: pointer; }\
.ok-button { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #fff; border: none; border-radius: 8px; padding: 0.75rem 1.5rem; font-size: 0.95rem; font-weight: 600; cursor: pointer; transition: all 0.3s; box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4); width: 100%; margin-top: 0.5rem; }\
.ok-button:hover { transform: translateY(-2px); box-shadow: 0 6px 20px rgba(102, 126, 234, 0.6); }\
.red-button { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: #fff; border: none; border-radius: 6px; padding: 0.4rem 0.8rem; font-size: 0.8rem; font-weight: 600; cursor: pointer; transition: all 0.3s; box-shadow: 0 2px 8px rgba(245, 87, 108, 0.4); text-decoration: none; display: inline-block; }\
.red-button:hover { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(245, 87, 108, 0.6); }\
.section { margin-bottom: 2rem; }\
@media (max-width: 768px) { body { padding: 0.5rem; } #container { padding: 1rem; border-radius: 12px; } h1 { font-size: 1.25rem; } h2 { font-size: 1rem; } .data-table { font-size: 0.8rem; display: block; overflow-x: auto; } .data-table th, .data-table td { padding: 0.5rem 0.25rem; font-size: 0.8rem; } td:first-child { font-size: 0.8rem; width: 35%; } input[type='text'], input[type='number'], select { font-size: 0.9rem; padding: 0.65rem; } }\
.modal-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); z-index: 1000; justify-content: center; align-items: center; }\
.modal-overlay.show { display: flex; }\
.modal-box { background: rgba(30, 30, 46, 0.98); border: 2px solid #f5576c; border-radius: 12px; padding: 1.5rem; max-width: 400px; text-align: center; box-shadow: 0 8px 32px rgba(245, 87, 108, 0.3); }\
.modal-box h3 { color: #f5576c; margin-bottom: 1rem; }\
.modal-box p { color: #e0e0e0; margin-bottom: 1.5rem; }\
.modal-box button { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #fff; border: none; border-radius: 8px; padding: 0.75rem 2rem; font-size: 1rem; cursor: pointer; }\
.green-button { background: linear-gradient(135deg, #4caf50 0%, #2e7d32 100%); color: #fff; border: none; border-radius: 6px; padding: 0.4rem 0.8rem; font-size: 0.8rem; font-weight: 600; cursor: pointer; transition: all 0.3s; box-shadow: 0 2px 8px rgba(76, 175, 80, 0.4); text-decoration: none; display: inline-block; }\
.select-button { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #fff; border: none; border-radius: 6px; padding: 0.4rem 0.8rem; font-size: 0.8rem; font-weight: 600; cursor: pointer; transition: all 0.3s; box-shadow: 0 2px 8px rgba(102, 126, 234, 0.4); text-decoration: none; display: inline-block; }\
.select-button:hover { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(102, 126, 234, 0.6); }\
.green-button:hover { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(76, 175, 80, 0.6); }\
</style>\
<script>\
function fillDhcpForm(mac, ip, name) {\
document.getElementById('dhcp_mac').value = mac;\
document.getElementById('dhcp_ip').value = ip;\
document.getElementById('dhcp_name').value = name;\
document.getElementById('dhcp_mac').scrollIntoView({behavior: 'smooth', block: 'center'});\
}\
</script>\
<body>"

/* After error modal, before logout section */
#define MAPPINGS_CHUNK_MID1 "\
<div id='container'>\
<div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;'>\
<div style='display: flex; align-items: center;'>\
<a href='/' style='display: inline-block; margin-right: 1rem;'><img src='/favicon.png' alt='Home' style='width: 64px; height: 64px; border: none;'></a>\
<h1 style='margin: 0;'>Mappings</h1>\
</div>"

/* After logout section, before clients tbody */
#define MAPPINGS_CHUNK_MID2 "\
</div>\
<div class='section'>\
<h2>Connected Clients</h2>\
<table class='data-table'>\
<thead>\
<tr>\
<th>MAC Address</th>\
<th>IP Address</th>\
<th>Device Name</th>\
<th>Traffic (TX / RX)</th>\
<th>Action</th>\
</tr>\
</thead>\
<tbody>"

/* Same header without the Traffic column (used when per-client stats are disabled) */
#define MAPPINGS_CHUNK_MID2_NOSTATS "\
</div>\
<div class='section'>\
<h2>Connected Clients</h2>\
<table class='data-table'>\
<thead>\
<tr>\
<th>MAC Address</th>\
<th>IP Address</th>\
<th>Device Name</th>\
<th>Action</th>\
</tr>\
</thead>\
<tbody>"

/* After clients tbody, before dhcp tbody */
#define MAPPINGS_CHUNK_MID3 "\
</tbody>\
</table>\
</div>\
<div class='section'>\
<h2>DHCP Reservations</h2>"

/* DHCP pool info streamed here */

#define MAPPINGS_CHUNK_MID3B "\
<table class='data-table'>\
<thead>\
<tr>\
<th>MAC Address</th>\
<th>IP Address</th>\
<th>Name</th>\
<th>Action</th>\
</tr>\
</thead>\
<tbody>"

/* After dhcp tbody, before portmap tbody */
#define MAPPINGS_CHUNK_MID4 "\
</tbody>\
</table>\
<h2>Add DHCP Reservation</h2>\
<form action='/mappings' method='GET'>\
<table>\
<tr><td>MAC Address</td><td><input type='text' name='dhcp_mac' id='dhcp_mac' placeholder='AA:BB:CC:DD:EE:FF'/></td></tr>\
<tr><td>IP Address</td><td><input type='text' name='dhcp_ip' id='dhcp_ip' placeholder='192.168.4.100'/></td></tr>\
<tr><td>Name (optional)</td><td><input type='text' name='dhcp_name' id='dhcp_name' placeholder='My Device'/></td></tr>\
<tr><td></td><td><input type='submit' name='dhcp_action' value='Add Reservation' class='ok-button'/>\
<input type='submit' name='dhcp_action' value='Block' class='red-button' style='width:100%;padding:0.75rem 1.5rem;font-size:0.95rem;border-radius:8px;margin-top:0.5rem;' onclick=\"document.getElementById('dhcp_ip').value='0.0.0.0';\"/></td></tr>\
</table>\
</form>\
</div>"

#define MAPPINGS_CHUNK_PORTFWD_HEAD "\
<div class='section'>\
<h2>Port Forwarding</h2>\
<table class='data-table' style='table-layout:fixed;'>\
<thead>\
<tr>\
<th>Interface</th>\
<th>Protocol</th>\
<th>Ext. Port</th>\
<th>Internal IP</th>\
<th>Int. Port</th>\
<th>Action</th>\
</tr>\
</thead>\
<tbody>"

#if CONFIG_ETH_UPLINK
#define PORTMAP_IFACE_OPTIONS "<option value='STA'>ETH (Ethernet)</option><option value='VPN'>VPN</option>"
#else
#define PORTMAP_IFACE_OPTIONS "<option value='STA'>STA (WiFi)</option><option value='VPN'>VPN</option>"
#endif

/* After portmap tbody to end */
#define MAPPINGS_CHUNK_PORTFWD_TAIL "\
</tbody>\
</table>\
<h2>Add Port Forwards</h2>\
<form action='/mappings' method='GET'>\
<table>\
<tr><td>Interface</td><td><select name='iface'>" PORTMAP_IFACE_OPTIONS "</select></td></tr>\
<tr><td>Protocol</td><td><select name='proto'><option value='TCP'>TCP</option><option value='UDP'>UDP</option></select></td></tr>\
<tr><td>External Port</td><td><input type='number' name='ext_port' min='1' max='65535' placeholder='8080'/></td></tr>\
<tr><td>Internal IP</td><td><input type='text' name='int_ip' placeholder='IP or device name'/></td></tr>\
<tr><td>Internal Port</td><td><input type='number' name='int_port' min='1' max='65535' placeholder='80'/></td></tr>\
<tr><td></td><td><input type='submit' name='port_action' value='Add Forward' class='ok-button'/></td></tr>\
</table>\
</form>\
</div>"

#define MAPPINGS_CHUNK_PAGE_FOOTER "\
<div style='margin-top: 2rem; text-align: center;'>\
<a href='/' style='padding: 0.75rem 2rem; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #fff; border: none; border-radius: 8px; text-decoration: none; font-size: 0.95rem; font-weight: 600; cursor: pointer; transition: all 0.3s; box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4); display: inline-block;'>&#127968; Home</a>\
</div>\
</div>\
</body>\
</html>"

