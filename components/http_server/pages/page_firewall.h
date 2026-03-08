/* Firewall page templates */
/* Firewall (ACL) Page */
/* Firewall Page - Chunked for streaming */
#define FIREWALL_CHUNK_HEAD "<html>\
<head>\
<meta name='viewport' content='width=device-width, initial-scale=1, maximum-scale=1, user-scalable=0'>\
<meta charset='UTF-8'>\
<title>Firewall</title>\
<link rel='icon' href='favicon.png'>\
</head>\
<style>\
* { box-sizing: border-box; margin: 0; padding: 0; }\
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: #e0e0e0; padding: 1rem; min-height: 100vh; line-height: 1.6; }\
h1 { font-size: 1.5rem; font-weight: 600; color: #00d9ff; margin-bottom: 1rem; text-shadow: 0 0 20px rgba(0, 217, 255, 0.3); }\
h2 { font-size: 1.1rem; font-weight: 500; color: #00d9ff; margin: 1.2rem 0 0.5rem 0; padding-bottom: 0.3rem; border-bottom: 1px solid rgba(0, 217, 255, 0.2); }\
h3 { font-size: 0.95rem; font-weight: 500; color: #f093fb; margin: 0.8rem 0 0.3rem 0; }\
#container { max-width: 900px; margin: 0 auto; padding: 1.5rem; background: rgba(30, 30, 46, 0.9); border-radius: 16px; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4); }\
.data-table { width: 100%; border-collapse: collapse; margin: 0.5rem 0; background: rgba(22, 33, 62, 0.6); border-radius: 8px; overflow: hidden; border: 1px solid rgba(0, 217, 255, 0.1); font-size: 0.8rem; }\
.data-table thead { background: rgba(0, 217, 255, 0.1); }\
.data-table th { padding: 0.4rem 0.2rem; text-align: left; font-weight: 600; color: #00d9ff; font-size: 0.75rem; }\
.data-table td { padding: 0.4rem 0.2rem; border-bottom: 1px solid rgba(255, 255, 255, 0.05); font-size: 0.75rem; }\
.data-table tbody tr:last-child td { border-bottom: none; }\
.data-table tbody tr:hover { background: rgba(0, 217, 255, 0.05); }\
table.form-table { width: 100%; border-collapse: collapse; }\
table.form-table td { padding: 0.3rem 0; vertical-align: top; }\
table.form-table td:first-child { color: #888; font-size: 0.8rem; padding-right: 0.5rem; width: 22%; text-align: right; }\
input[type='text'], input[type='number'], select { width: 100%; background: rgba(22, 33, 62, 0.6); border: 1px solid rgba(0, 217, 255, 0.2); border-radius: 6px; color: #e0e0e0; padding: 0.4rem; font-size: 0.85rem; }\
input:focus, select:focus { outline: none; border-color: #00d9ff; }\
.ok-button { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #fff; border: none; border-radius: 6px; padding: 0.5rem 1rem; font-size: 0.85rem; font-weight: 600; cursor: pointer; width: 100%; margin-top: 0.25rem; }\
.red-button { background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: #fff; border: none; border-radius: 4px; padding: 0.2rem 0.4rem; font-size: 0.7rem; font-weight: 600; cursor: pointer; text-decoration: none; display: inline-block; }\
.orange-button { background: linear-gradient(135deg, #ff9a56 0%, #ff6b35 100%); color: #fff; border: none; border-radius: 4px; padding: 0.2rem 0.4rem; font-size: 0.7rem; font-weight: 600; cursor: pointer; text-decoration: none; display: inline-block; }\
.acl-section { margin-bottom: 1rem; padding: 0.8rem; background: rgba(22, 33, 62, 0.4); border-radius: 10px; border: 1px solid rgba(0, 217, 255, 0.1); }\
.stats { font-size: 0.75rem; color: #888; margin-bottom: 0.3rem; }\
.stats span { margin-right: 0.8rem; }\
.stats .allowed { color: #4caf50; }\
.stats .denied { color: #f44336; }\
@media (max-width: 768px) { body { padding: 0.5rem; } #container { padding: 1rem; } .data-table { font-size: 0.65rem; display: block; overflow-x: auto; } .data-table th, .data-table td { padding: 0.2rem 0.1rem; font-size: 0.65rem; } }\
.modal-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); z-index: 1000; justify-content: center; align-items: center; }\
.modal-overlay.show { display: flex; }\
.modal-box { background: rgba(30, 30, 46, 0.98); border: 2px solid #f5576c; border-radius: 12px; padding: 1.5rem; max-width: 400px; text-align: center; box-shadow: 0 8px 32px rgba(245, 87, 108, 0.3); }\
.modal-box h3 { color: #f5576c; margin-bottom: 1rem; }\
.modal-box p { color: #e0e0e0; margin-bottom: 1.5rem; }\
.modal-box button { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #fff; border: none; border-radius: 6px; padding: 0.5rem 1.5rem; font-size: 0.9rem; font-weight: 600; cursor: pointer; }\
</style>\
<body>"

/* After error modal, before logout section */
#define FIREWALL_CHUNK_MID1 "\
<div id='container'>\
<div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;'>\
<div style='display: flex; align-items: center;'>\
<a href='/' style='display: inline-block; margin-right: 1rem;'><img src='/favicon.png' alt='Home' style='width: 64px; height: 64px; border: none;'></a>\
<h1 style='margin: 0;'>Firewall</h1>\
</div>"

/* After logout section, before ACL sections */
#define FIREWALL_CHUNK_MID2 "\
</div>\
<p style='color: #888; font-size: 0.8rem; margin-bottom: 0.8rem;'>Rules processed top-down. First match wins. No match = allow (permissive).</p>"

/* After ACL sections (add form and footer) */
#define FIREWALL_CHUNK_TAIL "\
<h2>Add ACL Rule</h2>\
<form action='/firewall' method='GET'>\
<table class='form-table'>\
<tr><td>Direction</td><td><select name='acl_list'>\
<option value='0'>Internet to ESP (to_esp)</option>\
<option value='1'>ESP to Internet (from_esp)</option>\
<option value='2'>Clients to ESP (to_ap)</option>\
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
<a href='/' style='padding: 0.6rem 1.5rem; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #fff; border: none; border-radius: 8px; text-decoration: none; font-size: 0.9rem; font-weight: 600;'>🏠 Home</a>\
</div>\
</div>\
</body>\
</html>"

