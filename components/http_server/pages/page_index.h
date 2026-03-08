/* Index page templates */
#include "router_config.h"

#if CONFIG_ETH_UPLINK
#define INDEX_TITLE "ESP32 NAT Router (LAN)"
#else
#define INDEX_TITLE "ESP32 NAT Router"
#endif

/* Index Page - Chunked for streaming */
#define INDEX_CHUNK_HEAD "<html>\
<head>\
<meta name='viewport' content='width=device-width, initial-scale=1, maximum-scale=1, user-scalable=0'>\
<meta charset='UTF-8'>\
<title>" INDEX_TITLE "</title>\
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
background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);\
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
width: 100%;\
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
width: 45%;\
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
background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);\
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
width: 50%;\
font-size: 0.8rem;\
}\
}\
</style>\
<body>\
<div id='container'>\
<div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;'>\
<div style='display: flex; align-items: center;'>\
<a href='/' style='display: inline-block; margin-right: 1rem;'><img src='/favicon.png' alt='Home' style='width: 64px; height: 64px; border: none;'></a>\
<h1 style='margin: 0;'>" INDEX_TITLE "</h1>\
</div>"
/* Logout button streamed here */

#define INDEX_CHUNK_STATUS_OPEN "\
</div>\
<h2>System Status</h2>\
<div class='status-table'>\
<table>"
/* Status rows streamed here */

#define INDEX_CHUNK_STATUS_CLOSE "\
</table>\
</div>"

#if !CONFIG_ETH_UPLINK
#define INDEX_CHUNK_BUTTONS "\
<div class='button-container'>\
<a href='/setup' class='nav-button'>🚀 Getting Started</a>\
<a href='/scan' class='nav-button'>📡 WiFi Scan</a>\
<a href='/config' class='nav-button'>⚙️ Configuration</a>\
<a href='/mappings' class='nav-button'>🔀 Mappings</a>\
<a href='/firewall' class='nav-button'>🛡️ Firewall</a>\
<a href='/vpn' class='nav-button'>🔒 VPN</a>\
</div>"
#else
#define INDEX_CHUNK_BUTTONS "\
<div class='button-container'>\
<a href='/config' class='nav-button'>⚙️ Configuration</a>\
<a href='/mappings' class='nav-button'>🔀 Mappings</a>\
<a href='/firewall' class='nav-button'>🛡️ Firewall</a>\
<a href='/vpn' class='nav-button'>🔒 VPN</a>\
</div>"
#endif
/* Auth UI streamed here */

#define INDEX_CHUNK_TAIL "\
<div style='margin-top: 2rem; padding-top: 1rem; border-top: 1px solid rgba(255, 255, 255, 0.1); text-align: center;'>\
<span style='color: #666; font-size: 0.75rem; font-family: monospace;'>v%s | Build: %s %s | ESP-IDF: "\
IDF_VER\
" | <a href='https://github.com/martin-ger/esp32_nat_router' target='_blank' rel='noopener' style='color: #00d9ff; text-decoration: none;'>Source</a></span>\
</div>\
</div>\
</body>\
</html>"

