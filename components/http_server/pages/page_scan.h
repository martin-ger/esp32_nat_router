/* WiFi Scan page templates */
#include "router_config.h"

/* WiFi Scan Page */
#define SCAN_PAGE "<html>\
<head>\
<meta name='viewport' content='width=device-width, initial-scale=1, maximum-scale=1, user-scalable=0'>\
<meta charset='UTF-8'>\
<meta http-equiv='refresh' content='%d'>\
<title>WiFi Scan</title>\
<link rel='icon' href='favicon.png'>\
</head>\
<style>\
* { box-sizing: border-box; margin: 0; padding: 0; }\
body {\
font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;\
background: linear-gradient(135deg, #0d000f 0%%, #120020 100%%);\
color: #cacad8; padding: 1rem; min-height: 100vh; line-height: 1.6;\
}\
h1 { font-size: 1.5rem; font-weight: 600; color: #a78bfa; margin-bottom: 1rem; text-shadow: 0 0 20px rgba(167, 139, 250, 0.3); }\
#container { max-width: 700px; margin: 0 auto; padding: 1.5rem; background: rgba(15, 5, 24, 0.96); border-radius: 16px; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4); }\
.data-table { width: 100%%; border-collapse: collapse; margin: 1rem 0; background: rgba(28, 8, 44, 0.6); border-radius: 12px; overflow: hidden; border: 1px solid rgba(167, 139, 250, 0.15); }\
.data-table thead { background: rgba(167, 139, 250, 0.15); }\
.data-table th { padding: 0.75rem 0.5rem; text-align: left; font-weight: 600; color: #a78bfa; font-size: 0.9rem; }\
.data-table td { padding: 0.75rem 0.5rem; border-bottom: 1px solid rgba(255, 255, 255, 0.05); font-size: 0.9rem; }\
.data-table tbody tr:last-child td { border-bottom: none; }\
.data-table tbody tr:hover { background: rgba(167, 139, 250, 0.08); }\
.signal-bars { display: inline-flex; align-items: flex-end; gap: 2px; height: 16px; vertical-align: middle; }\
.signal-bars .bar { width: 4px; border-radius: 1px; background: #444; }\
.signal-bars .bar.active.signal-excellent { background: #4caf50; }\
.signal-bars .bar.active.signal-good { background: #8bc34a; }\
.signal-bars .bar.active.signal-fair { background: #ffc107; }\
.signal-bars .bar.active.signal-weak { background: #ff9800; }\
.signal-bars .bar.active.signal-poor { background: #f44336; }\
.connect-button { background: linear-gradient(135deg, #7c3aed 0%%, #5b21b6 100%%); color: #fff; border: none; border-radius: 6px; padding: 0.4rem 0.8rem; font-size: 0.8rem; font-weight: 600; cursor: pointer; text-decoration: none; display: inline-block; }\
.connect-button:hover { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(124, 58, 237, 0.4); }\
.refresh-note { color: #888; font-size: 0.8rem; margin-bottom: 1rem; }\
@keyframes pulse { 0%%, 100%% { opacity: 1; } 50%% { opacity: 0.5; } }\
@media (max-width: 600px) { body { padding: 0.5rem; } #container { padding: 1rem; } .data-table th, .data-table td { padding: 0.5rem 0.25rem; font-size: 0.8rem; } }\
</style>\
<body>\
<div id='container'>\
<div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;'>\
<div style='display: flex; align-items: center;'>\
<a href='/' style='display: inline-block; margin-right: 1rem;'><img src='/favicon.png' alt='Home' style='width: 64px; height: 64px; border: none;'></a>\
<h1 style='margin: 0;'>WiFi Scan</h1>\
</div>\
</div>\
<p class='refresh-note'>Auto-refreshes every 15 seconds. Found %d networks.</p>\
<table class='data-table'>\
<thead>\
<tr>\
<th>SSID</th>\
<th>Signal</th>\
<th>Ch</th>\
<th>Security</th>\
%s\
</tr>\
</thead>\
<tbody>\
%s\
</tbody>\
</table>\
<div style='margin-top: 2rem; text-align: center;'>\
<a href='/' style='padding: 0.75rem 2rem; background: linear-gradient(135deg, #7c3aed 0%%, #5b21b6 100%%); color: #fff; border: none; border-radius: 8px; text-decoration: none; font-size: 0.95rem; font-weight: 600;'>🏠 Home</a>\
</div>\
</div>\
</body>\
</html>\
"
