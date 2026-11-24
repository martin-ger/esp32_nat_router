/* GPIO Sensor Monitor & Per-Sensor Graph/CSV Page Templates */
#pragma once

#define GPIO_CHUNK_HEAD "<html>\
<head>\
<meta name='viewport' content='width=device-width, initial-scale=1, maximum-scale=1, user-scalable=0'>\
<meta charset='UTF-8'>\
<title>GPIO Sensors</title>\
<link rel='icon' href='favicon.png'>\
</head>\
<style>\
* { box-sizing: border-box; margin: 0; padding: 0; }\
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: #e0e0e0; padding: 1rem; min-height: 100vh; line-height: 1.6; }\
h1 { font-size: 1.5rem; font-weight: 600; color: #00d9ff; margin-bottom: 1rem; text-shadow: 0 0 20px rgba(0, 217, 255, 0.3); }\
h2 { font-size: 1.15rem; font-weight: 500; color: #00d9ff; margin: 1.5rem 0 0.75rem 0; padding-bottom: 0.5rem; border-bottom: 1px solid rgba(0, 217, 255, 0.2); }\
#container { max-width: 800px; margin: 0 auto; padding: 1.5rem; background: rgba(30, 30, 46, 0.9); border-radius: 16px; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4); backdrop-filter: blur(10px); }\
.data-table { width: 100%; border-collapse: collapse; margin: 1rem 0; background: rgba(22, 33, 62, 0.6); border-radius: 12px; overflow: hidden; border: 1px solid rgba(0, 217, 255, 0.1); }\
.data-table th { padding: 0.7rem 0.5rem; text-align: left; font-weight: 600; color: #00d9ff; font-size: 0.85rem; background: rgba(0, 217, 255, 0.1); }\
.data-table td { padding: 0.7rem 0.5rem; border-bottom: 1px solid rgba(255, 255, 255, 0.05); font-size: 0.9rem; color: #e0e0e0; text-align: left; }\
.data-table tr:last-child td { border-bottom: none; }\
table.form-tbl { width: 100%; border-collapse: collapse; }\
table.form-tbl td { padding: 0.45rem 0; vertical-align: middle; }\
table.form-tbl td:first-child { color: #888; font-size: 0.9rem; padding-right: 0.75rem; width: 32%; text-align: right; }\
input[type='text'], input[type='number'], select { width: 100%; background: rgba(22, 33, 62, 0.6); border: 1px solid rgba(0, 217, 255, 0.2); border-radius: 8px; color: #e0e0e0; padding: 0.65rem; font-size: 0.95rem; }\
input:focus, select:focus { outline: none; border-color: #00d9ff; }\
.switch-wrap { display: flex; align-items: center; justify-content: space-between; padding: 1rem; background: rgba(22, 33, 62, 0.6); border: 1px solid rgba(0, 217, 255, 0.2); border-radius: 12px; margin: 1rem 0; }\
.switch { position: relative; display: inline-block; width: 52px; height: 28px; }\
.switch input { opacity: 0; width: 0; height: 0; }\
.slider { position: absolute; cursor: pointer; inset: 0; background: #444; border-radius: 28px; transition: .25s; }\
.slider:before { position: absolute; content: ''; height: 22px; width: 22px; left: 3px; bottom: 3px; background: #fff; border-radius: 50%; transition: .25s; }\
input:checked + .slider { background: #00d9ff; }\
input:checked + .slider:before { transform: translateX(24px); background: #1a1a2e; }\
.ok-button { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #fff; border: none; border-radius: 8px; padding: 0.75rem 1.5rem; font-size: 0.95rem; font-weight: 600; cursor: pointer; width: 100%; margin-top: 0.5rem; text-decoration: none; display: inline-block; text-align: center; }\
.btn-sm { padding: 0.35rem 0.65rem; border-radius: 6px; font-size: 0.8rem; font-weight: 600; text-decoration: none; color: #fff; display: inline-block; margin-right: 0.25rem; }\
.btn-blue { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }\
.btn-green { background: linear-gradient(135deg, #4caf50 0%, #2e7d32 100%); }\
.btn-red { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }\
.err-box { background: rgba(244, 67, 54, 0.15); border: 1px solid #f44336; color: #ff8a80; padding: 0.75rem; border-radius: 8px; margin: 0.75rem 0; font-size: 0.9rem; }\
@media (max-width: 600px) { body { padding: 0.5rem; } #container { padding: 1rem; } .data-table { display: block; overflow-x: auto; } }\
</style>\
<body>\
<div id='container'>\
<div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;'>\
<div style='display: flex; align-items: center;'>\
<a href='/' style='display: inline-block; margin-right: 1rem;'><img src='/favicon.png' alt='Home' style='width: 64px; height: 64px; border: none;'></a>\
<h1 style='margin: 0;'>GPIO</h1>\
</div>"

#define GPIO_CHUNK_TOGGLE "\
</div>\
<form action='/gpio' method='GET'>\
<input type='hidden' name='set_en' value='1'/>\
<div class='switch-wrap'>\
<div>\
<strong style='color:#00d9ff;'>Enable GPIO Sensor Logging</strong><br>\
<small style='color:#888;'>Logs selected GPIO pins on a timer and unlocks per-sensor graphs &amp; CSV export. Uses 0 RAM when off.</small>\
</div>\
<label class='switch'>\
<input type='checkbox' name='en' value='1' %s onchange='this.form.submit()'/>\
<span class='slider'></span>\
</label>\
</div>\
</form>"

#define GPIO_CHUNK_TABLE_OPEN "\
<h2>Configured Sensors</h2>\
<table class='data-table'>\
<thead><tr><th>Name</th><th>Pin</th><th>Mode</th><th>Interval</th><th>Current</th><th>Actions</th></tr></thead>\
<tbody>"

/* Format args: heading, slot_val, name_val, gpio_val, mode0_sel, mode1_sel,
 * ival_val, u_hr_sel, u_min_sel, u_sec_sel, persist_chk, btn_label, cancel_link */
#define GPIO_CHUNK_ADD_FORM "\
</tbody></table>\
<h2>%s</h2>\
<form action='/gpio' method='GET'>\
<input type='hidden' name='add_sensor' value='1'/>\
<input type='hidden' name='slot' value='%d'/>\
<table class='form-tbl'>\
<tr><td>Name</td><td><input type='text' name='name' value='%s' placeholder='MQ135_Air' maxlength='23' required/></td></tr>\
<tr><td>GPIO Pin</td><td><input type='number' name='gpio' min='0' max='48' value='%s' placeholder='34' required/></td></tr>\
<tr><td>Mode</td><td><select name='mode'>\
<option value='0' %s>Analog (ADC1 - Wi-Fi safe)</option>\
<option value='1' %s>Digital (HIGH / LOW)</option>\
</select></td></tr>\
<tr><td>Measure Every</td><td>\
<div style='display:flex;gap:0.5rem;'>\
<input type='number' name='ival' min='1' max='86400' value='%lu' style='width:45%%;' required/>\
<select name='iunit' style='width:55%%;'>\
<option value='3600' %s>Hours</option>\
<option value='60' %s>Minutes</option>\
<option value='1' %s>Seconds</option>\
</select>\
</div>\
</td></tr>\
<tr><td>Persist</td><td><label style='color:#aaa;font-size:0.85rem;'><input type='checkbox' name='persist' value='1' %s/> Save CSV to flash (/data, requires &ge; 60s interval)</label></td></tr>\
<tr><td></td><td><input type='submit' value='%s' class='ok-button'/>%s</td></tr>\
</table>\
<small style='display:block;color:#888;margin-top:0.5rem;'>Analog sensors require ADC1 pins (ESP32: 32-39, S3: 1-10, C3: 0-4, C5: 1-6, C6: 0-6) because ADC2 conflicts with Wi-Fi. Use a voltage divider if your sensor outputs 5V.</small>\
</form>"

#define GPIO_CHUNK_TAIL "\
<div style='margin-top: 1.5rem; text-align: center;'>\
<a href='/' style='padding: 0.75rem 2rem; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #fff; border-radius: 8px; text-decoration: none; font-weight: 600; display: inline-block;'>&#127968; Home</a>\
</div>\
</div></body></html>"

/* --- Per-Sensor Page (/gpio/sensor?id=X) --- */

#define GPIO_SENSOR_CHUNK_HEAD "<html>\
<head>\
<meta name='viewport' content='width=device-width, initial-scale=1, maximum-scale=1, user-scalable=0'>\
<meta charset='UTF-8'>\
<title>GPIO Sensor</title>\
<link rel='icon' href='/favicon.png'>\
</head>\
<style>\
* { box-sizing: border-box; margin: 0; padding: 0; }\
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: #e0e0e0; padding: 1rem; min-height: 100vh; }\
#container { max-width: 820px; margin: 0 auto; padding: 1.5rem; background: rgba(30, 30, 46, 0.9); border-radius: 16px; box-shadow: 0 8px 32px rgba(0,0,0,0.4); }\
h1 { font-size: 1.4rem; color: #00d9ff; margin: 0; }\
h2 { font-size: 1.05rem; color: #00d9ff; margin: 1.25rem 0 0.6rem 0; padding-bottom: 0.35rem; border-bottom: 1px solid rgba(0,217,255,0.2); }\
.card-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 0.75rem; margin: 1rem 0; }\
.card { background: rgba(22,33,62,0.7); border: 1px solid rgba(0,217,255,0.18); border-radius: 10px; padding: 0.85rem; text-align: center; }\
.card .lbl { font-size: 0.75rem; color: #888; text-transform: uppercase; }\
.card .val { font-size: 1.35rem; font-weight: 700; color: #00d9ff; margin-top: 0.2rem; }\
.card .sub { font-size: 0.8rem; color: #aaa; }\
.actions { display: flex; flex-wrap: wrap; gap: 0.6rem; margin: 0.75rem 0 1rem 0; }\
.btn { padding: 0.55rem 1rem; border-radius: 8px; text-decoration: none; color: #fff; font-size: 0.88rem; font-weight: 600; border: none; cursor: pointer; }\
.btn-blue { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }\
.btn-green { background: linear-gradient(135deg, #4caf50 0%, #2e7d32 100%); }\
.btn-red { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); }\
.chart-box { background: rgba(15, 22, 42, 0.85); border: 1px solid rgba(0,217,255,0.18); border-radius: 12px; padding: 0.75rem; }\
canvas { width: 100%; height: 220px; display: block; }\
.data-table { width: 100%; border-collapse: collapse; margin-top: 0.75rem; background: rgba(22,33,62,0.6); border-radius: 10px; overflow: hidden; font-size: 0.85rem; }\
.data-table th { padding: 0.55rem; text-align: left; color: #00d9ff; background: rgba(0,217,255,0.1); }\
.data-table td { padding: 0.5rem 0.55rem; border-bottom: 1px solid rgba(255,255,255,0.05); }\
</style>\
<body><div id='container'>\
<div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:0.75rem;'>\
<div style='display:flex;align-items:center;'>\
<a href='/' style='margin-right:0.85rem;'><img src='/favicon.png' alt='Home' style='width:48px;height:48px;'></a>"

/* Dynamic title, simple view cards, and action links streamed in http_server.c */

#define GPIO_SENSOR_CHUNK_GRAPH "\
<h2>History Graph</h2>\
<div class='chart-box'>\
<canvas id='chart' width='760' height='220'></canvas>\
<div id='chartMeta' style='color:#888;font-size:0.8rem;margin-top:0.35rem;'>Loading samples...</div>\
</div>\
<h2>Recent Readings</h2>\
<table class='data-table'>\
<thead><tr><th>Time</th><th>Raw</th><th>Voltage / State</th></tr></thead>\
<tbody id='tblBody'></tbody>\
</table>\
<div style='margin-top:1.5rem;text-align:center;'>\
<a href='/gpio' class='btn btn-blue' style='margin-right:0.5rem;'>&larr; All GPIO</a>\
<a href='/' class='btn btn-blue'>&#127968; Home</a>\
</div>\
<script>\
(function(){\
var id=new URLSearchParams(location.search).get('id')||'0';\
function fmtT(s){if(s.t>0){var d=new Date(s.t*1000);return d.toLocaleString();}var h=Math.floor(s.u/3600),m=Math.floor((s.u%3600)/60),sec=s.u%60;return 'Up '+h+'h '+m+'m '+sec+'s';}\
function draw(d){\
var pts=d.samples||[], cv=document.getElementById('chart'), ctx=cv.getContext('2d');\
var W=cv.width, H=cv.height, padL=48, padR=14, padT=16, padB=26;\
ctx.clearRect(0,0,W,H);\
var meta=document.getElementById('chartMeta');\
if(!pts.length){meta.textContent='No samples yet. Click Measure Now to take the first reading.';ctx.fillStyle='#888';ctx.font='14px sans-serif';ctx.fillText('No data yet',W/2-35,H/2);return;}\
var isDig=(d.mode===1);\
var vals=pts.map(function(p){return isDig?p.raw:p.mv;});\
var mn=isDig?0:Math.min.apply(null,vals), mx=isDig?1:Math.max.apply(null,vals);\
if(mn===mx){mn=Math.max(0,mn-10);mx=mx+10;}\
var minEl=document.getElementById('vMin'), maxEl=document.getElementById('vMax'), curEl=document.getElementById('vCur'), subEl=document.getElementById('vSub');\
var last=pts[pts.length-1];\
if(curEl)curEl.textContent=isDig?(last.raw?'HIGH':'LOW'):(last.mv+' mV');\
if(subEl)subEl.textContent=isDig?('Raw: '+last.raw):('Raw: '+last.raw+' | '+fmtT(last));\
if(minEl)minEl.textContent=isDig?(Math.min.apply(null,vals)+' '):(Math.min.apply(null,vals)+' mV');\
if(maxEl)maxEl.textContent=isDig?(Math.max.apply(null,vals)+' '):(Math.max.apply(null,vals)+' mV');\
meta.textContent=pts.length+' sample(s) recorded | Latest: '+fmtT(last);\
ctx.strokeStyle='rgba(255,255,255,0.08)';ctx.lineWidth=1;ctx.fillStyle='#888';ctx.font='11px monospace';\
for(var g=0;g<=4;g++){var y=padT+(H-padT-padB)*g/4, v=Math.round(mx-(mx-mn)*g/4);ctx.beginPath();ctx.moveTo(padL,y);ctx.lineTo(W-padR,y);ctx.stroke();ctx.fillText(isDig?v:(v+'mV'),4,y+4);}\
ctx.beginPath();\
for(var i=0;i<pts.length;i++){var x=pts.length===1?(padL+W-padR)/2:padL+(W-padL-padR)*i/(pts.length-1);var y=padT+(H-padT-padB)*(1-(vals[i]-mn)/(mx-mn));if(i===0)ctx.moveTo(x,y);else ctx.lineTo(x,y);}\
ctx.strokeStyle='#00d9ff';ctx.lineWidth=2.2;ctx.stroke();\
for(var i=0;i<pts.length;i++){var x=pts.length===1?(padL+W-padR)/2:padL+(W-padL-padR)*i/(pts.length-1);var y=padT+(H-padT-padB)*(1-(vals[i]-mn)/(mx-mn));ctx.fillStyle='#00d9ff';ctx.beginPath();ctx.arc(x,y,2.8,0,Math.PI*2);ctx.fill();}\
ctx.fillStyle='#888';ctx.fillText(fmtT(pts[0]),padL,H-6);if(pts.length>1){var rt=fmtT(last);ctx.fillText(rt,W-padR-ctx.measureText(rt).width,H-6);}\
var tb=document.getElementById('tblBody'), rows='';\
for(var j=pts.length-1;j>=Math.max(0,pts.length-25);j--){var p=pts[j];rows+='<tr><td>'+fmtT(p)+'</td><td>'+p.raw+'</td><td>'+(isDig?(p.raw?'HIGH':'LOW'):(p.mv+' mV'))+'</td></tr>';}\
tb.innerHTML=rows;\
}\
function load(){fetch('/api/gpio-data?id='+encodeURIComponent(id)).then(function(r){return r.json();}).then(draw);}\
load();setInterval(load,15000);\
})();\
</script>\
</div></body></html>"