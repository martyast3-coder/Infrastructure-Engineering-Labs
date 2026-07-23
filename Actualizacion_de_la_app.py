import threading, json, time, queue, ipaddress, os, io, zipfile
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, unquote
import paramiko, webbrowser

# ── Config ───────────────────────────────────────────────────────
PORT_WEB = 8080
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKUP_DIR = os.path.join(SCRIPT_DIR, "backups")
os.makedirs(BACKUP_DIR, exist_ok=True)

# ── Estado global ────────────────────────────────────────────────
ssh_client      = None
ssh_lock        = threading.Lock()
monitor_active  = False
monitor_queue   = queue.Queue()
last_backup_batch = {"mikrotik": [], "juniper": []}   # último lote de backups exitosos por fabricante (para el ZIP)
backup_lock     = threading.Lock()

def exec_cmd(cmd, timeout=15):
    with ssh_lock:
        if not ssh_client:
            return None, "Sin conexión SSH."
        try:
            _, o, e = ssh_client.exec_command(cmd, timeout=timeout)
            return o.read().decode(), e.read().decode()
        except Exception as ex:
            return None, str(ex)

def parse_ip_range(text, max_ips=5000):
    """
    Acepta:
      - CIDR:            10.250.250.0/24
      - Rango completo:  10.250.250.1-10.250.250.254
      - Rango corto:      10.250.250.1-254
      - IP única:         10.250.250.5
      - Varias entradas separadas por coma
    Devuelve una lista de IPs (str), sin duplicados, en el orden encontrado.
    """
    text = (text or "").strip()
    if not text:
        return []
    ips = []
    parts = [p.strip() for p in text.split(",") if p.strip()]
    for part in parts:
        if "/" in part:
            net = ipaddress.ip_network(part, strict=False)
            if net.num_addresses > max_ips:
                raise ValueError(f"La red {part} tiene demasiadas direcciones ({net.num_addresses}).")
            hosts = list(net.hosts())
            if not hosts:  # /31 o /32 en versiones antiguas de ipaddress
                hosts = [net.network_address]
            ips.extend(str(ip) for ip in hosts)
        elif "-" in part:
            start_str, end_str = [x.strip() for x in part.split("-", 1)]
            start_ip = ipaddress.ip_address(start_str)
            if "." in end_str:
                end_ip = ipaddress.ip_address(end_str)
            else:
                base_octets = start_str.split(".")
                base_octets[-1] = end_str
                end_ip = ipaddress.ip_address(".".join(base_octets))
            start_i, end_i = int(start_ip), int(end_ip)
            if end_i < start_i:
                start_i, end_i = end_i, start_i
            if (end_i - start_i + 1) > max_ips:
                raise ValueError(f"El rango {part} tiene demasiadas direcciones.")
            cur = start_i
            while cur <= end_i:
                ips.append(str(ipaddress.ip_address(cur)))
                cur += 1
        else:
            ips.append(part)
        if len(ips) > max_ips:
            raise ValueError("Demasiadas direcciones IP en el rango solicitado.")
    seen, out = set(), []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out

def _safe_filename(ip, vendor="mikrotik"):
    ts = time.strftime("%Y%m%d_%H%M%S")
    return f"{vendor}_{ip.replace('.', '-')}_{ts}.txt"

# Comando de export de configuración por fabricante
VENDOR_EXPORT_CMD = {
    "mikrotik": "/export",
    "juniper":  "show configuration | no-more",
}

# ── HTML ─────────────────────────────────────────────────────────
HTML = r"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>MANAGEMENT</title>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Syne:wght@700;800&display=swap" rel="stylesheet"/>
<style>
:root{--bg:#080c10;--panel:#0e1419;--panel2:#141c23;--border:#1e2d3d;
--accent:#00d4ff;--green:#00ff88;--red:#ff4466;--yellow:#ffcc00;
--fg:#cdd9e5;--fg2:#546e7a;--mono:'JetBrains Mono',monospace;--display:'Syne',sans-serif}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--fg);font-family:var(--mono);min-height:100vh}
body::before{content:'';position:fixed;inset:0;
background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,212,255,.012) 2px,rgba(0,212,255,.012) 4px);
pointer-events:none;z-index:999}
header{display:flex;align-items:center;justify-content:space-between;
padding:14px 28px;background:var(--panel);border-bottom:1px solid var(--border);
position:sticky;top:0;z-index:100}
.logo{display:flex;align-items:center;gap:10px}
.logo img{height:52px;width:auto;display:block;background:#fff;padding:8px 14px;border-radius:8px}
.logo span{color:var(--fg2);font-size:.72rem;font-family:var(--mono);font-weight:400;letter-spacing:1px}
#status-badge{display:flex;align-items:center;gap:8px;font-size:.8rem;padding:5px 14px;
border-radius:3px;border:1px solid var(--border);background:var(--panel2)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--red);transition:.3s}
.dot.on{background:var(--green);box-shadow:0 0 8px var(--green)}
.conn-panel{display:flex;flex-wrap:wrap;gap:10px;align-items:flex-end;
padding:16px 28px;background:var(--panel);border-bottom:1px solid var(--border)}
.field{display:flex;flex-direction:column;gap:4px}
.field label{font-size:.68rem;color:var(--fg2);text-transform:uppercase;letter-spacing:1px}
.field input{background:var(--panel2);border:1px solid var(--border);color:var(--fg);
font-family:var(--mono);font-size:.85rem;padding:7px 12px;border-radius:3px;
outline:none;width:160px;transition:.2s}
.field input:focus{border-color:var(--accent);box-shadow:0 0 0 2px rgba(0,212,255,.15)}
.btn{padding:8px 18px;border:none;border-radius:3px;font-family:var(--mono);
font-size:.82rem;font-weight:600;cursor:pointer;transition:.15s;letter-spacing:.5px}
.btn-accent{background:var(--accent);color:#000}.btn-accent:hover{background:#33deff}
.btn-ghost{background:transparent;color:var(--fg2);border:1px solid var(--border)}
.btn-ghost:hover{border-color:var(--fg2);color:var(--fg)}
.btn-red{background:var(--red);color:#fff}
.tabs{display:flex;padding:0 28px;background:var(--panel);border-bottom:1px solid var(--border);flex-wrap:wrap}
.tab{padding:12px 20px;font-size:.82rem;cursor:pointer;border-bottom:2px solid transparent;color:var(--fg2);transition:.15s}
.tab:hover{color:var(--fg)}.tab.active{color:var(--accent);border-bottom-color:var(--accent)}
.content{padding:22px 28px;max-width:1200px}
.pane{display:none}.pane.active{display:block}
.card{background:var(--panel);border:1px solid var(--border);border-radius:4px;padding:20px;margin-bottom:16px}
.card-title{font-size:.75rem;color:var(--fg2);text-transform:uppercase;letter-spacing:2px;
margin-bottom:14px;display:flex;align-items:center;gap:8px}
.card-title::before{content:'';display:block;width:3px;height:14px;background:var(--accent);border-radius:2px}
.log{background:#040709;border:1px solid var(--border);border-radius:3px;
padding:14px;height:320px;overflow-y:auto;font-size:.8rem;line-height:1.7}
.log::-webkit-scrollbar{width:4px}.log::-webkit-scrollbar-thumb{background:var(--border)}
.log .ok{color:var(--green)}.log .err{color:var(--red)}
.log .info{color:var(--accent)}.log .warn{color:var(--yellow)}
.log .ts{color:var(--fg2);margin-right:8px;font-size:.72rem}
.inline-form{display:flex;gap:10px;align-items:flex-end;flex-wrap:wrap;margin-bottom:14px}
.hint{font-size:.72rem;color:var(--fg2);margin-bottom:10px}
.tbl{width:100%;border-collapse:collapse;font-size:.8rem}
.tbl th{text-align:left;padding:8px 12px;font-size:.68rem;color:var(--fg2);
text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid var(--border)}
.tbl td{padding:9px 12px;border-bottom:1px solid rgba(30,45,61,.5)}
.tbl tr:hover td{background:var(--panel2)}
.badge{display:inline-block;padding:2px 8px;border-radius:2px;font-size:.7rem;font-weight:700;letter-spacing:.5px}
.badge.up{background:rgba(0,255,136,.12);color:var(--green);border:1px solid rgba(0,255,136,.3)}
.badge.down{background:rgba(255,68,102,.12);color:var(--red);border:1px solid rgba(255,68,102,.3)}
.info-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
@media(max-width:700px){.info-grid{grid-template-columns:1fr}}
.info-block{background:#040709;border:1px solid var(--border);border-radius:3px;padding:14px}
.info-block h4{font-size:.7rem;color:var(--accent);text-transform:uppercase;letter-spacing:2px;margin-bottom:10px}
.info-block pre{font-size:.78rem;color:var(--fg);white-space:pre-wrap;line-height:1.6}
.cmd-bar{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap}
.cmd-bar input{flex:1;min-width:220px;background:#040709;border:1px solid var(--border);color:var(--fg);
font-family:var(--mono);font-size:.85rem;padding:8px 14px;border-radius:3px;outline:none}
.cmd-bar input:focus{border-color:var(--accent)}
.mon-header{display:flex;gap:10px;align-items:center;margin-bottom:14px;flex-wrap:wrap}
.snapshot{background:#040709;border:1px solid var(--border);border-left:3px solid var(--accent);
border-radius:3px;padding:12px 16px;margin-bottom:10px;font-size:.78rem;line-height:1.6}
.snapshot .snap-time{color:var(--fg2);font-size:.7rem;margin-bottom:6px}
.mon-log{height:380px;overflow-y:auto}.mon-log::-webkit-scrollbar{width:4px}
.mon-log::-webkit-scrollbar-thumb{background:var(--border)}
/* RADIUS / BACKUP grid */
.radius-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px;margin-top:14px}
.radius-card{border:1px solid var(--border);border-radius:4px;padding:14px 16px;position:relative;overflow:hidden}
.radius-card::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px}
.radius-card.ok{background:rgba(0,255,136,.05);border-color:rgba(0,255,136,.25)}
.radius-card.ok::before{background:var(--green)}
.radius-card.no_radius{background:rgba(255,204,0,.07);border-color:rgba(255,204,0,.3)}
.radius-card.no_radius::before{background:var(--yellow)}
.radius-card.warning{background:rgba(255,204,0,.07);border-color:rgba(255,204,0,.3)}
.radius-card.warning::before{background:var(--yellow)}
.radius-card.error{background:rgba(255,68,102,.05);border-color:rgba(255,68,102,.25)}
.radius-card.error::before{background:var(--red)}
.radius-card.unreachable{background:rgba(84,110,122,.06);border-color:rgba(84,110,122,.2)}
.radius-card.unreachable::before{background:var(--fg2)}
.r-ip{font-weight:700;font-size:.9rem;color:var(--fg);margin-bottom:4px}
.r-msg{font-size:.75rem;margin-bottom:6px}
.radius-card.ok .r-msg{color:var(--green)}
.radius-card.no_radius .r-msg,.radius-card.warning .r-msg{color:var(--yellow)}
.radius-card.error .r-msg{color:var(--red)}
.radius-card.unreachable .r-msg{color:var(--fg2)}
.r-detail{font-size:.7rem;color:var(--fg2);white-space:pre-wrap;max-height:55px;overflow-y:auto}
.radius-summary{display:flex;gap:12px;flex-wrap:wrap;margin:10px 0}
.rs{font-size:.78rem;padding:4px 12px;border-radius:3px;font-weight:600}
.s-ok{background:rgba(0,255,136,.15);color:var(--green)}
.s-warn{background:rgba(255,204,0,.15);color:var(--yellow)}
.s-err{background:rgba(255,68,102,.15);color:var(--red)}
.s-off{background:rgba(84,110,122,.15);color:var(--fg2)}
.prog{height:3px;background:var(--border);border-radius:2px;margin:8px 0;overflow:hidden;display:none}
.prog-bar{height:100%;background:var(--accent);width:0%;transition:width .3s}
.dl-link{display:inline-block;margin-top:6px;text-decoration:none;font-size:.72rem}
</style>
</head>
<body>
<header>
  <div class="logo"><img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAABIkAAAJkCAYAAACVuHE+AAAAAXNSR0IArs4c6QAAAERlWElmTU0AKgAAAAgAAYdpAAQAAAABAAAAGgAAAAAAA6ABAAMAAAABAAEAAKACAAQAAAABAAAEiaADAAQAAAABAAACZAAAAACyDJe4AABAAElEQVR4AezdS3bbxrbwcYDWOUlPuu04S7wjsO4IxNOT3bHuCMSMwNIAbMP2AKiMwPQIIndi9wKPIPIIQi077U/qJbkS8e1NiKIk8wGABaAef65FiQ+gatev+AA2C4Uo4oIAAggggAACCCCAAAIIIIAAAggggAACCCCAAAIIIIAAAggggAACCCCAAAIIIIAAAggggAACCCCAAAIIIIAAAggggAACCCCAAAIIIIAAAggggAACCCCAAAIIIIAAAggggAACCCCAAAIIIIAAAggggAACCCCAAAIIIIAAAggggAACCCCAAAIIIIAAAggggAACCCCAAAIIIIAAAggggAACCCCAAAIIIIAAAggggAACCCCAAAII5AIxEAgggAACCCAQjkB3P9m6/OvBThxl3ayTdee1PMvi8ziLTzeiq9HoYzKatwyPIYAAAggggAACCPgnYEWS6OHem57S3t9gjbPOaZZF51nn6vzPX5NT//hpEQIIIIAAAvUKaFLo6q/OfhTHvSzKelLbdskaL2T50yyKTqJ4nPJ9XFKPxRFAAAEEEEAAAYcEGk8SdfeS7v/Fnf04i3qSFdoRq+Ibq3H0WX/ZjLIsfRCNU37ddOiVRqgIIIAAAo0K/Lj3ui+JHUkORU8NV3wm5R7/67vxcHSSnBsum+IQQAABBBBAAAEEWhRoJEl0kxiKokNpa/Gk0CoYSRrJSKMhG6qroHgeAQQQQCAEgcmhZP/Eh1Em1yjarLvNcRS/e5BdJfxoU7c05SOAAAIIIIAAAs0I1Jok0uTQVfwgkeHtB3U3hw3VuoUpHwEEEEDAZoHJyKE4OpYYa08OfeuQ/bzxXZYwsuhbGR5BAAEEEEAAAQRcEqglSdRkcug+9iRZ9N3VIRuq92W4jwACCCDgo8APTxKZhLozjLLoUcvtu5Dv4P6XD89PWo6D6hFAAAEEEEAAAQQqChhPEj188ippapj7kjZfyJxHh18+vhguWYanEEAAAQQQcFrgh8evD+WLfGBTI/ixxqbeIBYEEEAAAQQQQKCcgLEkkY4euux0Tiz4JXMmkEXvN74f9xlVNCPhFgIIIICAHwI/Pn4zbOJw7kpaMmfgxni8z1xFlfRYCQEEEEAAAQQQaE3ASJJocgr7ONPh5S3Mg7DS7iyLx/ucsnelEwsggAACCDggkE9O3Umt+lFmvtuFfP/2+P6dj8OjCCCAAAIIIICAjQKddYPSiTKjOPtNyrExQaTN246zTjpJZK3bWNZHAAEEEECgRQGHEkSqtKnfvzpnUotkVI0AAggggAACCCBQQmCtJNH1mVTelqivrUU3NZE1SWi1FQH1IoAAAgggsIaAYwmiaUtJFE0l+I8AAggggAACCDggUDlJ5FCC6KYbsjh6K3M47N88wA0EEEAAAQQcEbj8y4ozmFXRmiSKNMlVZWXWQQABBBBAAAEEEGhOoFKSSBMtmnBpLkxzNckkn0OGvpvzpCQEEEAAgfoFJmcOjaOn9ddUWw2bl//IPEpcEEAAAQQQQAABBKwWKD1xtSZYdI4BaZWtcxAVAb/Y+G7c5axnRahYBgEEEECgTYHrk0Po3H8eXLKfv354eehBQ2gCAggggAACCCDgpUCpkUQ6VDyOZLi72wki7cjNy787J3qDCwIIIIAAArYKTA7RirOhrfGVjyt+xokkyquxBgIIIIAAAggg0JRAqSTR5d9x4sApd4va7f7w+DW/ZhbVYjkEEEAAgcYFJt+7cpbOxiuus8JOdlxn8ZSNAAIIIIAAAgggUF2g8OFm14eZ/V69KivXvNjIxjujj8nIyugICgEEEEAgWIHuXtK9jDt/+AiQRdHRnx9ekCzysXNpEwIIIIAAAgg4LVB4JJHMQ+TjxtzmVfwgcboHCR4BBBBAwEsBn7+f5BeqhLOdefmypVEIIIAAAggg4LhAoSTR9Wnjdx1v69zw5WxnB/pr7dwneRABBBBAAIEWBPR7Sb+fWqi6qSo3/+/vTr+pyqgHAQQQQAABBBBAoJhAoSRRFmdJseLcXMrnX2vd7BGiRgABBMIWCOF7SUYTMS9g2C9zWo8AAggggAACFgqsTBJNzkKSRY8sjN1YSIwmMkZJQQgggAACBgTke2nfQDG2F7F9PVLZ9jiJDwEEEEAAAQQQCEZgZZIojqN+CBqXnTiIdobQl7QRAQQQcFngx73XfYl/0+U2lIg9hGRYCQ4WRQABBBBAAAEE2hVYmiTSSSU9nxNhpp+RJJphcAsBBBBAoC0BOfNXMImTQEZMtfVSol4EEEAAAQQQQKC0wNIk0dVfnWA2VEVu+4cnyU5pQVZAAAEEEEDApEAc9UwWZ3lZm5PD2i0PkvAQQAABBBBAAIFQBJYmiaI47oUCoe2MozikpFhIXUtbEUAAAScErn+sCOVQs7xPOuOeE51DkAgggAACCCCAQAACS5NEMgy8F4DBrIlZWEmxWcO5hQACCCBghUDW6VkRR5NBjGNG8TbpTV0IIIAAAggggMASgYVJIp2PSNbbXrKuj0+xoepjr9ImBBBAwBGBOMq6joRqLsw44rvXnCYlIYAAAggggAACawksTBJd/vUgxI22ze5e0l1LlJURQAABBBCoLBDkqJrQfpCq/OpgRQQQQAABBBBAoG6BhUmiKNA5Ai6jB9260SkfAQQQQAABBGYC/EAzs+AWAggggAACCCDQpsDiJFGbUbVYd5BD/Vv0pmoEEEAAgTsCu3fuBXKHH2gC6WiaiQACCCCAAALWCyxMEsVZp2t99DUEmHUCnA+iBkeKRAABBBBAAAEEEEAAAQQQQAABtwQWJonkzGZdt5pCtAgggAACCCCAAAIIIIAAAggggAACVQUWJomqFsh6CCCAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAkcq/PiBgBBBBAAAEEEEAAAQQQQAABBBAwLkCSyDgpBSKAAAIIIIAAAggggAACCCCAAALuCZAk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vW5wbk1L7SpTQvVeuJcFjnTefRPz20w51xkmfT5SQeMs5ts6G9opdjk66+wut2Z/hh93KxWH0q16zSi2Pc6swz8rEnX44OoaAQIECBAgQIAAgawC6SvUy9uA/hBx0wVck6Z0K0oqJuxTKGrOxfyhRMui3z5Wyxl+ErecTZYXZn1fFjimEXMU80XMTTv3IqW7UTqpODSOeZ4WNHJKuZWf4d9Efi9jftvAPL+PnO6LQ7MG5tfplD7udO90jgABAgQIECBAgACB/ALl6I7rKA6MI/gk5jRC4ZOYDz2lC9zrmKdx4bt43/gsXi/f/7ztS4pRZZrHzi+qBIh9j1H4OI92f6qYd9p9lCHG5hDlyJyr2PAqzr3TeJ3EPI7505gPPaVzbx5zOneu4/y7jdf2TGWRcHKX8GVxFq/jmNPr85gPPTXJMn0Oqxqkc6K107C1mUucAAECBAgQIECAAIHmCJQX7aeR0Cjm9HoScx3TPILexnyzcsRGmcfVDg3PIs5sh+1Xb3pZTGPFePXKjUsXscXjQtfGHbJtUHqdR7xRhZgp93mF/avtWj48+zSCjGMePZqrXuxHqLvpdfw3nXPzmBcxp3PvJl67N622TLa5isCvIlayTH7l/FDgjUVHnqp/HuZxbkyP3ItKzQ8r7W1nAgQIECBAgAABAgQIECDQZIFyxNuuGS7iYn+x606d334/y1RUS4UhEwECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECBAgQIECAAAECbRT4f6pR5Oj98Y9iAAAAAElFTkSuQmCC" alt="HDCO Group"/></div>
  <div id="status-badge"><div class="dot" id="dot"></div><span id="status-text">Desconectado</span></div>
</header>
<div class="conn-panel">
  <div class="field"><label>Host IP</label><input id="f-host" value="10.250.250.1"/></div>
  <div class="field"><label>Puerto SSH</label><input id="f-port" value="7722" style="width:80px"/></div>
  <div class="field"><label>Usuario</label><input id="f-user" value="admin"/></div>
  <div class="field"><label>Contraseña</label><input id="f-pass" type="password" value=""/></div>
  <button class="btn btn-accent" onclick="connectSSH()">Conectar</button>
  <button class="btn btn-ghost"  onclick="disconnectSSH()">Desconectar</button>
</div>
<div class="tabs">
  <div class="tab active" onclick="switchTab('ping',this)">📡 Ping</div>
  <div class="tab" onclick="switchTab('ifaces',this)">🔌 Interfaces</div>
  <div class="tab" onclick="switchTab('sysinfo',this)">ℹ️ Sistema</div>
  <div class="tab" onclick="switchTab('cmd',this)">💻 Comandos</div>
  <div class="tab" onclick="switchTab('monitor',this)">📊 Monitor</div>
  <div class="tab" onclick="switchTab('radius',this)">🔐 RADIUS</div>
  <div class="tab" onclick="switchTab('backup',this)">💾 Backup</div>
</div>
<div class="content">
  <!-- Ping -->
  <div class="pane active" id="pane-ping">
    <div class="card">
      <div class="card-title">Ping desde el equipo</div>
      <div class="inline-form">
        <div class="field"><label>Destino</label><input id="ping-ip" value="8.8.8.8"/></div>
        <div class="field"><label>Count</label><input id="ping-count" value="4" style="width:70px"/></div>
        <button class="btn btn-accent" onclick="doPing()">Ejecutar Ping</button>
        <button class="btn btn-ghost"  onclick="clearLog('ping-log')">Limpiar</button>
      </div>
      <div class="log" id="ping-log"></div>
    </div>
  </div>
  <!-- Interfaces -->
  <div class="pane" id="pane-ifaces">
    <div class="card">
      <div class="card-title">Interfaces del Router</div>
      <button class="btn btn-accent" onclick="loadIfaces()" style="margin-bottom:14px">Actualizar</button>
      <div style="overflow-x:auto">
        <table class="tbl">
          <thead><tr><th>Nombre</th><th>Tipo</th><th>MAC Address</th><th>MTU</th><th>TX</th><th>RX</th><th>Estado</th></tr></thead>
          <tbody id="iface-body"><tr><td colspan="7" style="color:var(--fg2);padding:20px">Conecta y presiona Actualizar</td></tr></tbody>
        </table>
      </div>
    </div>
  </div>
  <!-- Sistema -->
  <div class="pane" id="pane-sysinfo">
    <div class="card">
      <div class="card-title">Información del Sistema</div>
      <button class="btn btn-accent" onclick="loadSysinfo()" style="margin-bottom:14px">Cargar Info</button>
      <div class="info-grid" id="info-grid"><div class="info-block"><h4>—</h4><pre>Conecta y presiona Cargar Info</pre></div></div>
    </div>
  </div>
  <!-- Comandos -->
  <div class="pane" id="pane-cmd">
    <div class="card">
      <div class="card-title">Terminal de Comandos</div>
      <div class="hint">Escribe cualquier comando compatible con el equipo conectado (RouterOS, Junos CLI, o cualquier otro shell accesible por SSH). El comando se envía tal cual por SSH, sin restricciones de sintaxis.</div>
      <div class="cmd-bar">
        <input id="cmd-input" placeholder="Escribe cualquier comando…" onkeydown="if(event.key==='Enter')runCmd()"/>
        <button class="btn btn-accent" onclick="runCmd()">Ejecutar</button>
        <button class="btn btn-ghost" onclick="downloadCmdLog()">⬇ Descargar salida</button>
        <button class="btn btn-ghost" onclick="clearLog('cmd-log')">Limpiar</button>
      </div>
      <div class="log" id="cmd-log"></div>
    </div>
  </div>
  <!-- Monitor -->
  <div class="pane" id="pane-monitor">
    <div class="card">
      <div class="card-title">Monitor en Tiempo Real</div>
      <div class="mon-header">
        <div class="field"><label>Intervalo (s)</label><input id="mon-interval" value="5" style="width:70px"/></div>
        <button class="btn btn-accent" id="mon-btn" onclick="toggleMonitor()">▶ Iniciar Monitor</button>
      </div>
      <div class="mon-log" id="mon-log"></div>
    </div>
  </div>
  <!-- RADIUS -->
  <div class="pane" id="pane-radius">
    <div class="card">
      <div class="card-title">Verificación RADIUS en la red</div>
      <div class="inline-form">
        <div class="field" style="flex:1;min-width:280px">
          <label>Rango IP (CIDR o guión)</label>
          <input id="rad-range" placeholder="10.250.250.0/24  ó  10.250.250.1-10.250.250.50" value="10.250.250.0/24" style="width:100%"/>
        </div>
        <div class="field"><label>Usuario</label><input id="rad-user" value="admin" style="width:90px"/></div>
        <div class="field"><label>Contraseña</label><input id="rad-pass" type="password" style="width:100px"/></div>
        <div class="field"><label>Puerto SSH</label><input id="rad-port" value="7722" style="width:70px"/></div>
        <button class="btn btn-accent" onclick="scanRadius()">🔍 Escanear</button>
        <button class="btn btn-ghost"  onclick="clearRadius()">Limpiar</button>
      </div>
      <div class="hint">Formatos válidos: CIDR (10.250.250.0/24), rango completo (10.250.250.1-10.250.250.254), rango corto (10.250.250.1-254) o varios separados por coma.</div>
      <div class="prog" id="rad-prog"><div class="prog-bar" id="rad-bar"></div></div>
      <div id="rad-summary" class="radius-summary"></div>
      <div class="radius-grid" id="radius-grid"></div>
    </div>
  </div>
  <!-- Backup -->
  <div class="pane" id="pane-backup">
    <div class="card">
      <div class="card-title">Backup masivo de configuración</div>
      <div class="tabs" style="padding:0;margin-bottom:16px;background:transparent;border-bottom:1px solid var(--border)">
        <div class="tab active" onclick="switchVendor('mikrotik',this)">🟦 MikroTik</div>
        <div class="tab" onclick="switchVendor('juniper',this)">🟧 Juniper</div>
      </div>

      <!-- MikroTik backup -->
      <div class="vendor-pane" id="vendor-mikrotik">
        <div class="inline-form">
          <div class="field" style="flex:1;min-width:280px">
            <label>Rango IP (CIDR o guión)</label>
            <input id="bk-range-mikrotik" placeholder="10.250.250.0/24  ó  10.250.250.1-10.250.250.50" value="10.250.250.0/24" style="width:100%"/>
          </div>
          <div class="field"><label>Usuario</label><input id="bk-user-mikrotik" value="admin" style="width:90px"/></div>
          <div class="field"><label>Contraseña</label><input id="bk-pass-mikrotik" type="password" style="width:110px"/></div>
          <div class="field"><label>Puerto SSH</label><input id="bk-port-mikrotik" value="7722" style="width:80px"/></div>
          <button class="btn btn-accent" onclick="doBackup('mikrotik')">⬇ Descargar Configuraciones</button>
          <button class="btn btn-ghost" onclick="clearBackup('mikrotik')">Limpiar</button>
        </div>
        <div class="hint">
          Se conecta a cada equipo del rango, ejecuta <code>/export</code> (RouterOS) y guarda el resultado como .txt en el
          servidor (carpeta <code>backups/</code>). Luego puedes descargar cada archivo por separado, o todos juntos en un
          ZIP para subirlos a OneDrive u otro almacenamiento.
        </div>
        <div class="prog" id="bk-prog-mikrotik"><div class="prog-bar" id="bk-bar-mikrotik"></div></div>
        <div id="bk-summary-mikrotik" class="radius-summary"></div>
        <button class="btn btn-ghost" id="bk-zip-btn-mikrotik" onclick="downloadZip('mikrotik')" style="display:none;margin-bottom:14px">📦 Descargar todo (ZIP)</button>
        <div class="radius-grid" id="backup-grid-mikrotik"></div>
      </div>

      <!-- Juniper backup -->
      <div class="vendor-pane" id="vendor-juniper" style="display:none">
        <div class="inline-form">
          <div class="field" style="flex:1;min-width:280px">
            <label>Rango IP (CIDR o guión)</label>
            <input id="bk-range-juniper" placeholder="10.250.250.0/24  ó  10.250.250.1-10.250.250.50" value="10.250.250.0/24" style="width:100%"/>
          </div>
          <div class="field"><label>Usuario</label><input id="bk-user-juniper" value="admin" style="width:90px"/></div>
          <div class="field"><label>Contraseña</label><input id="bk-pass-juniper" type="password" style="width:110px"/></div>
          <div class="field"><label>Puerto SSH</label><input id="bk-port-juniper" value="22" style="width:80px"/></div>
          <button class="btn btn-accent" onclick="doBackup('juniper')">⬇ Descargar Configuraciones</button>
          <button class="btn btn-ghost" onclick="clearBackup('juniper')">Limpiar</button>
        </div>
        <div class="hint">
          Se conecta a cada equipo del rango por SSH, ejecuta <code>show configuration | no-more</code> (Junos) y guarda
          el resultado como .txt en el servidor (carpeta <code>backups/</code>). Luego puedes descargar cada archivo por
          separado, o todos juntos en un ZIP para subirlos a OneDrive u otro almacenamiento.
        </div>
        <div class="prog" id="bk-prog-juniper"><div class="prog-bar" id="bk-bar-juniper"></div></div>
        <div id="bk-summary-juniper" class="radius-summary"></div>
        <button class="btn btn-ghost" id="bk-zip-btn-juniper" onclick="downloadZip('juniper')" style="display:none;margin-bottom:14px">📦 Descargar todo (ZIP)</button>
        <div class="radius-grid" id="backup-grid-juniper"></div>
      </div>
    </div>
  </div>
</div>
<script>
let monitoring=false, monSource=null;

function switchTab(n,el){
  document.querySelectorAll('.pane').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.getElementById('pane-'+n).classList.add('active');
  el.classList.add('active');
}
function appendLog(id,text,cls=''){
  const el=document.getElementById(id);
  const ts=new Date().toLocaleTimeString();
  const d=document.createElement('div');
  d.innerHTML=`<span class="ts">[${ts}]</span><span class="${cls}">${esc(text)}</span>`;
  el.appendChild(d); el.scrollTop=el.scrollHeight;
}
function clearLog(id){document.getElementById(id).innerHTML='';}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function setStatus(on,msg){
  document.getElementById('dot').className='dot'+(on?' on':'');
  document.getElementById('status-text').textContent=msg;
}
async function api(path,body=null){
  const opts={method:body?'POST':'GET',headers:{'Content-Type':'application/json'}};
  if(body) opts.body=JSON.stringify(body);
  const r=await fetch(path,opts);
  return r.json();
}
async function connectSSH(){
  setStatus(false,'Conectando…');
  const d=await api('/api/connect',{
    host:document.getElementById('f-host').value,
    port:document.getElementById('f-port').value,
    user:document.getElementById('f-user').value,
    password:document.getElementById('f-pass').value
  });
  if(d.ok) setStatus(true,`Conectado · ${document.getElementById('f-host').value}`);
  else     setStatus(false,'Desconectado');
  alert(d.msg);
}
async function disconnectSSH(){
  if(monitoring)await toggleMonitor();
  await api('/api/disconnect',{});
  setStatus(false,'Desconectado');
}
async function doPing(){
  const ip=document.getElementById('ping-ip').value;
  const count=document.getElementById('ping-count').value;
  appendLog('ping-log',`Ping → ${ip} (count=${count})`,'info');
  const d=await api('/api/ping',{ip,count});
  if(!d.ok){appendLog('ping-log',d.msg,'err');return;}
  d.output.split('\n').forEach(l=>{
    if(!l.trim())return;
    appendLog('ping-log',l,l.includes('ms')?'ok':l.toLowerCase().includes('timeout')?'err':'');
  });
}
async function loadIfaces(){
  const d=await api('/api/interfaces');
  const tb=document.getElementById('iface-body');
  if(!d.ok){tb.innerHTML=`<tr><td colspan="7" style="color:var(--red)">${esc(d.msg)}</td></tr>`;return;}
  tb.innerHTML=d.interfaces.map(i=>{
    const up=(i.flags||'').includes('R');
    return `<tr><td><b>${i.name||'—'}</b></td><td style="color:var(--fg2)">${i.type||'—'}</td>
    <td style="color:var(--accent)">${i['mac-address']||'—'}</td><td>${i.mtu||'—'}</td>
    <td>${i['tx-byte']||'—'}</td><td>${i['rx-byte']||'—'}</td>
    <td><span class="badge ${up?'up':'down'}">${up?'▲ UP':'▼ DOWN'}</span></td></tr>`;
  }).join('');
}
async function loadSysinfo(){
  const d=await api('/api/sysinfo');
  if(!d.ok)return;
  document.getElementById('info-grid').innerHTML=Object.entries(d.data).map(([t,c])=>`
    <div class="info-block"><h4>${t}</h4><pre>${esc(c||'Sin datos')}</pre></div>`).join('');
}
async function runCmd(){
  const cmd=document.getElementById('cmd-input').value.trim();
  if(!cmd)return;
  appendLog('cmd-log','$ '+cmd,'info');
  const d=await api('/api/command',{cmd});
  if(!d.ok){appendLog('cmd-log',d.msg,'err');return;}
  d.output.split('\n').forEach(l=>{if(l.trim())appendLog('cmd-log',l);});
  if(d.error)appendLog('cmd-log',d.error,'err');
}
function downloadCmdLog(){
  const log=document.getElementById('cmd-log');
  const text=Array.from(log.children).map(d=>d.textContent).join('\n');
  if(!text.trim()){alert('No hay salida para descargar.');return;}
  const blob=new Blob([text],{type:'text/plain'});
  const url=URL.createObjectURL(blob);
  const a=document.createElement('a');
  const ts=new Date().toISOString().replace(/[:.]/g,'-');
  a.href=url; a.download=`comando_${ts}.txt`;
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}
async function toggleMonitor(){
  if(!monitoring){
    const interval=document.getElementById('mon-interval').value;
    await api('/api/monitor/start',{interval});
    monSource=new EventSource('/api/monitor/stream');
    monSource.onmessage=e=>{const d=JSON.parse(e.data);if(d.type==='snapshot')addSnap(d);};
    monitoring=true;
    document.getElementById('mon-btn').textContent='■ Detener Monitor';
    document.getElementById('mon-btn').style.background='var(--red)';
  }else{
    await api('/api/monitor/stop',{});
    if(monSource){monSource.close();monSource=null;}
    monitoring=false;
    document.getElementById('mon-btn').textContent='▶ Iniciar Monitor';
    document.getElementById('mon-btn').style.background='var(--accent)';
  }
}
function addSnap(data){
  const log=document.getElementById('mon-log');
  const el=document.createElement('div');
  el.className='snapshot';
  el.innerHTML=`<div class="snap-time">⏱ ${data.time}</div><pre>${esc(data.output||'')}</pre>`;
  log.prepend(el);
}
async function scanRadius(){
  const range=document.getElementById('rad-range').value.trim();
  const user=document.getElementById('rad-user').value.trim();
  const pwd=document.getElementById('rad-pass').value;
  const port=document.getElementById('rad-port').value;
  const grid=document.getElementById('radius-grid');
  const summ=document.getElementById('rad-summary');
  grid.innerHTML=`<div style="color:var(--fg2);padding:10px">Escaneando ${esc(range)}…</div>`;
  summ.innerHTML='';
  const prog=document.getElementById('rad-prog');
  const bar=document.getElementById('rad-bar');
  prog.style.display='block'; bar.style.width='0%';
  let pct=0;
  const ticker=setInterval(()=>{pct=Math.min(pct+3,90);bar.style.width=pct+'%';},400);
  const d=await api('/api/radius',{range,user,password:pwd,port});
  clearInterval(ticker); bar.style.width='100%';
  setTimeout(()=>{prog.style.display='none';},700);
  if(!d.ok){grid.innerHTML=`<div style="color:var(--red);padding:10px">${esc(d.msg||'Error')}</div>`;return;}
  const all=d.results||[];
  const visible=all.filter(r=>r.status!=='unreachable');
  const ok=all.filter(r=>r.status==='ok').length;
  const warn=all.filter(r=>r.status==='no_radius'||r.status==='warning').length;
  const err=all.filter(r=>r.status==='error').length;
  const off=all.filter(r=>r.status==='unreachable').length;
  summ.innerHTML=`<span class="rs s-ok">✔ RADIUS OK: ${ok}</span>
    <span class="rs s-warn">⚠ Sin RADIUS: ${warn}</span>
    <span class="rs s-err">✘ Error: ${err}</span>
    <span class="rs s-off">○ Offline: ${off}</span>`;
  if(!visible.length){
    grid.innerHTML='<div style="color:var(--fg2);padding:10px">No se encontraron equipos accesibles.</div>';
    return;
  }
  const sorted=[...visible].sort((a,b)=>({no_radius:0,warning:1,error:2,ok:3}[a.status]??9)-({no_radius:0,warning:1,error:2,ok:3}[b.status]??9));
  const icon={ok:'✔',warning:'⚠',no_radius:'⚠',error:'✘',unreachable:'○'};
  grid.innerHTML=sorted.map(r=>`
    <div class="radius-card ${r.status}">
      <div class="r-ip">📍 ${r.ip}</div>
      <div class="r-msg">${icon[r.status]||'?'} ${esc(r.msg)}</div>
      ${r.servers.length?`<div class="r-detail">${esc(r.servers.join('\n'))}</div>`:''}
    </div>`).join('');
}
function clearRadius(){
  document.getElementById('radius-grid').innerHTML='';
  document.getElementById('rad-summary').innerHTML='';
}
function switchVendor(v,el){
  document.querySelectorAll('.vendor-pane').forEach(p=>p.style.display='none');
  document.getElementById('vendor-'+v).style.display='block';
  el.parentElement.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  el.classList.add('active');
}
async function doBackup(vendor){
  const range=document.getElementById('bk-range-'+vendor).value.trim();
  const user=document.getElementById('bk-user-'+vendor).value.trim();
  const pwd=document.getElementById('bk-pass-'+vendor).value;
  const port=document.getElementById('bk-port-'+vendor).value;
  const grid=document.getElementById('backup-grid-'+vendor);
  const summ=document.getElementById('bk-summary-'+vendor);
  const zipBtn=document.getElementById('bk-zip-btn-'+vendor);
  grid.innerHTML=`<div style="color:var(--fg2);padding:10px">Conectando y exportando configuración de ${esc(range)}…</div>`;
  summ.innerHTML=''; zipBtn.style.display='none';
  const prog=document.getElementById('bk-prog-'+vendor);
  const bar=document.getElementById('bk-bar-'+vendor);
  prog.style.display='block'; bar.style.width='0%';
  let pct=0;
  const ticker=setInterval(()=>{pct=Math.min(pct+2,90);bar.style.width=pct+'%';},500);
  const d=await api('/api/backup',{range,user,password:pwd,port,vendor});
  clearInterval(ticker); bar.style.width='100%';
  setTimeout(()=>{prog.style.display='none';},700);
  if(!d.ok){grid.innerHTML=`<div style="color:var(--red);padding:10px">${esc(d.msg||'Error')}</div>`;return;}
  const all=d.results||[];
  const ok=all.filter(r=>r.status==='ok').length;
  const err=all.filter(r=>r.status==='error').length;
  const off=all.filter(r=>r.status==='unreachable').length;
  summ.innerHTML=`<span class="rs s-ok">✔ Descargadas: ${ok}</span>
    <span class="rs s-err">✘ Error: ${err}</span>
    <span class="rs s-off">○ Offline: ${off}</span>`;
  if(ok>0) zipBtn.style.display='inline-block';
  const visible=all.filter(r=>r.status!=='unreachable');
  if(!visible.length){grid.innerHTML='<div style="color:var(--fg2);padding:10px">No se encontraron equipos accesibles.</div>';return;}
  const icon={ok:'✔',error:'✘',unreachable:'○'};
  grid.innerHTML=visible.map(r=>`
    <div class="radius-card ${r.status}">
      <div class="r-ip">📍 ${r.ip}</div>
      <div class="r-msg">${icon[r.status]||'?'} ${esc(r.msg)}</div>
      ${r.filename?`<a class="btn btn-ghost dl-link" href="/api/download/${encodeURIComponent(r.filename)}" download>⬇ Descargar .txt (${(r.size/1024).toFixed(1)} KB)</a>`:''}
    </div>`).join('');
}
function downloadZip(vendor){ window.location.href='/api/download-zip?vendor='+encodeURIComponent(vendor); }
function clearBackup(vendor){
  document.getElementById('backup-grid-'+vendor).innerHTML='';
  document.getElementById('bk-summary-'+vendor).innerHTML='';
  document.getElementById('bk-zip-btn-'+vendor).style.display='none';
}
</script>
</body></html>"""

# ── HTTP Handler ─────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args): pass  # silenciar logs

    def send_json(self, data, code=200):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        n = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(n)) if n else {}

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/":
            body = HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/status":
            self.send_json({"connected": ssh_client is not None})
        elif path == "/api/interfaces":
            self._interfaces()
        elif path == "/api/sysinfo":
            self._sysinfo()
        elif path == "/api/monitor/stream":
            self._stream()
        elif path.startswith("/api/download/"):
            self._download_file(path[len("/api/download/"):])
        elif path == "/api/download-zip":
            from urllib.parse import parse_qs
            qs = parse_qs(parsed.query)
            vendor = qs.get("vendor", ["mikrotik"])[0]
            self._download_zip(vendor)
        else:
            self.send_json({"error": "not found"}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        data = self.read_json()
        if   path == "/api/connect":         self.send_json(self._connect(data))
        elif path == "/api/disconnect":      self.send_json(self._disconnect())
        elif path == "/api/ping":            self.send_json(self._ping(data))
        elif path == "/api/command":         self.send_json(self._command(data))
        elif path == "/api/monitor/start":   self.send_json(self._mon_start(data))
        elif path == "/api/monitor/stop":    self.send_json(self._mon_stop())
        elif path == "/api/radius":          self.send_json(self._radius(data))
        elif path == "/api/backup":          self.send_json(self._backup(data))
        else: self.send_json({"error": "not found"}, 404)

    # ── API methods ──────────────────────────────────────────────
    def _connect(self, d):
        global ssh_client
        try:
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            c.connect(d["host"], port=int(d.get("port", 7722)),
                      username=d["user"], password=d["password"],
                      timeout=10, look_for_keys=False, allow_agent=False)
            with ssh_lock:
                if ssh_client: ssh_client.close()
                ssh_client = c
            return {"ok": True, "msg": f"Conectado a {d['host']}"}
        except paramiko.AuthenticationException:
            return {"ok": False, "msg": "Autenticación fallida. Verifica usuario y contraseña."}
        except Exception as e:
            return {"ok": False, "msg": str(e)}

    def _disconnect(self):
        global ssh_client, monitor_active
        monitor_active = False
        with ssh_lock:
            if ssh_client: ssh_client.close(); ssh_client = None
        return {"ok": True}

    def _ping(self, d):
        out, err = exec_cmd(f"/ping {d.get('ip','8.8.8.8')} count={d.get('count',4)}")
        if out is None: return {"ok": False, "msg": err}
        return {"ok": True, "output": out, "error": err}

    def _interfaces(self):
        out, err = exec_cmd("/interface print detail")
        if out is None: self.send_json({"ok": False, "msg": err}); return
        ifaces, cur = [], {}
        for line in out.splitlines():
            line = line.strip()
            if not line: continue
            if line.startswith("Flags:"):
                if cur.get("name"): ifaces.append(cur)
                cur = {"flags": line}
            else:
                for tok in line.split():
                    if "=" in tok:
                        k,v = tok.split("=",1); cur[k]=v
        if cur.get("name"): ifaces.append(cur)
        self.send_json({"ok": True, "interfaces": ifaces})

    def _sysinfo(self):
        cmds = [("/system identity print","Identidad"),("/system resource print","Recursos"),
                ("/system routerboard print","RouterBoard"),("/ip address print","Direcciones IP")]
        result = {}
        for cmd, title in cmds:
            out, err = exec_cmd(cmd)
            result[title] = out if out else err
        self.send_json({"ok": True, "data": result})

    def _command(self, d):
        cmd = d.get("cmd","").strip()
        if not cmd: return {"ok": False, "msg": "Comando vacío."}
        out, err = exec_cmd(cmd)
        if out is None: return {"ok": False, "msg": err}
        return {"ok": True, "output": out, "error": err}

    def _mon_start(self, d):
        global monitor_active
        if monitor_active: return {"ok": False, "msg": "Ya activo."}
        monitor_active = True
        threading.Thread(target=_monitor_loop, args=(int(d.get("interval",5)),), daemon=True).start()
        return {"ok": True}

    def _mon_stop(self):
        global monitor_active
        monitor_active = False
        return {"ok": True}

    def _stream(self):
        self.send_response(200)
        self.send_header("Content-Type","text/event-stream")
        self.send_header("Cache-Control","no-cache")
        self.end_headers()
        try:
            while True:
                try:
                    msg = monitor_queue.get(timeout=25)
                    self.wfile.write(f"data: {json.dumps(msg)}\n\n".encode())
                    self.wfile.flush()
                except queue.Empty:
                    self.wfile.write(b"data: {\"type\":\"ping\"}\n\n")
                    self.wfile.flush()
        except: pass

    def _radius(self, d):
        ip_range = d.get("range", "")
        user = d.get("user", "admin")
        pwd  = d.get("password", "")
        port = int(d.get("port", 7722) or 7722)
        try:
            ips = parse_ip_range(ip_range)
        except Exception as e:
            return {"ok": False, "msg": f"Rango inválido: {e}"}
        if not ips:
            return {"ok": False, "msg": "Rango vacío o inválido."}
        if len(ips) > 1024:
            return {"ok": False, "msg": "Demasiadas IPs (máx 1024). Reduce el rango."}

        results = []
        lock = threading.Lock()

        def check(ip):
            entry = {"ip":ip,"status":"unreachable","enabled":False,"servers":[],"msg":"Sin respuesta"}
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                c.connect(ip, port=port, username=user, password=pwd,
                          timeout=6, look_for_keys=False, allow_agent=False)
            except paramiko.AuthenticationException:
                entry["status"] = "error"; entry["msg"] = "Auth fallida"
                with lock:
                    results.append(entry)
                return
            except Exception:
                entry["status"] = "unreachable"; entry["msg"] = "Sin respuesta"
                with lock:
                    results.append(entry)
                return

            # A partir de aquí ya hubo conexión y autenticación exitosas.
            # Cualquier problema para leer RADIUS se clasifica como "no_radius",
            # nunca como "unreachable" (offline), porque el equipo sí responde.
            try:
                _, o, e = c.exec_command("/radius print", timeout=10)
                raw = o.read().decode(errors="replace")
                err = e.read().decode(errors="replace")
                servers = [l.strip() for l in raw.splitlines()
                           if l.strip() and not l.strip().startswith("Flags") and not l.strip().startswith("#")]
                has = bool(servers)
                disabled = all("X" in l[:6] for l in servers) if servers else True
                entry["servers"] = servers
                entry["enabled"] = has and not disabled
                if has and not disabled:
                    entry["status"] = "ok"; entry["msg"] = "RADIUS activo"
                elif has:
                    entry["status"] = "warning"; entry["msg"] = "RADIUS desactivado"
                else:
                    entry["status"] = "no_radius"
                    extra = err.strip().splitlines()[0][:80] if err.strip() else ""
                    entry["msg"] = "Sin RADIUS configurado" + (f" ({extra})" if extra else "")
            except Exception:
                entry["status"] = "no_radius"
                entry["servers"] = []
                entry["msg"] = "Sin RADIUS configurado (no se pudo leer la configuración)"
            finally:
                try: c.close()
                except Exception: pass
            with lock:
                results.append(entry)

        threads = [threading.Thread(target=check, args=(ip,)) for ip in ips]
        MAXCONC = 40
        for i in range(0, len(threads), MAXCONC):
            batch = threads[i:i+MAXCONC]
            for t in batch: t.start()
            for t in batch: t.join()
        results.sort(key=lambda x: [int(p) for p in x["ip"].split(".")])
        return {"ok": True, "results": results}

    def _backup(self, d):
        ip_range = d.get("range", "")
        user = d.get("user", "admin")
        pwd  = d.get("password", "")
        vendor = d.get("vendor", "mikrotik")
        if vendor not in VENDOR_EXPORT_CMD:
            return {"ok": False, "msg": f"Fabricante desconocido: {vendor}"}
        default_port = 7722 if vendor == "mikrotik" else 22
        port = int(d.get("port", default_port) or default_port)
        export_cmd = VENDOR_EXPORT_CMD[vendor]
        try:
            ips = parse_ip_range(ip_range)
        except Exception as e:
            return {"ok": False, "msg": f"Rango inválido: {e}"}
        if not ips:
            return {"ok": False, "msg": "Rango vacío o inválido."}
        if len(ips) > 512:
            return {"ok": False, "msg": "Demasiadas IPs (máx 512 por lote). Reduce el rango."}

        results = []
        lock = threading.Lock()

        def do_one(ip):
            entry = {"ip": ip, "status": "unreachable", "msg": "Sin respuesta", "filename": None, "size": 0}
            try:
                c = paramiko.SSHClient()
                c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                c.connect(ip, port=port, username=user, password=pwd,
                          timeout=8, look_for_keys=False, allow_agent=False)
                _, o, e = c.exec_command(export_cmd, timeout=20)
                out = o.read().decode(errors="replace")
                err = e.read().decode(errors="replace")
                c.close()
                if not out.strip():
                    entry["status"] = "error"
                    entry["msg"] = err.strip() or "Export vacío"
                else:
                    fname = _safe_filename(ip, vendor)
                    fpath = os.path.join(BACKUP_DIR, fname)
                    header = f"# Backup de {ip} ({vendor}) - {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
                    with open(fpath, "w", encoding="utf-8") as f:
                        f.write(header + out)
                    entry["status"] = "ok"
                    entry["msg"] = "Configuración descargada"
                    entry["filename"] = fname
                    entry["size"] = os.path.getsize(fpath)
            except paramiko.AuthenticationException:
                entry["status"] = "error"; entry["msg"] = "Auth fallida"
            except Exception:
                entry["status"] = "unreachable"; entry["msg"] = "Sin respuesta"
            with lock:
                results.append(entry)

        threads = [threading.Thread(target=do_one, args=(ip,)) for ip in ips]
        MAXCONC = 20
        for i in range(0, len(threads), MAXCONC):
            batch = threads[i:i+MAXCONC]
            for t in batch: t.start()
            for t in batch: t.join()

        results.sort(key=lambda x: [int(p) for p in x["ip"].split(".")])
        with backup_lock:
            last_backup_batch[vendor] = [r for r in results if r["status"] == "ok"]
        return {"ok": True, "results": results, "vendor": vendor}

    def _download_file(self, fname):
        fname = os.path.basename(unquote(fname))
        fpath = os.path.join(BACKUP_DIR, fname)
        if not fname or not os.path.isfile(fpath):
            self.send_json({"error": "not found"}, 404); return
        with open(fpath, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
        self.send_header("Content-Length", len(data))
        self.end_headers()
        self.wfile.write(data)

    def _download_zip(self, vendor="mikrotik"):
        with backup_lock:
            batch = list(last_backup_batch.get(vendor, []))
        if not batch:
            self.send_json({"error": "No hay backups recientes en memoria."}, 404); return
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            for entry in batch:
                fpath = os.path.join(BACKUP_DIR, entry["filename"])
                if os.path.isfile(fpath):
                    z.write(fpath, arcname=entry["filename"])
        data = buf.getvalue()
        self.send_response(200)
        self.send_header("Content-Type", "application/zip")
        ts = time.strftime("%Y%m%d_%H%M%S")
        self.send_header("Content-Disposition", f'attachment; filename="backups_{vendor}_{ts}.zip"')
        self.send_header("Content-Length", len(data))
        self.end_headers()
        self.wfile.write(data)

def _monitor_loop(interval):
    while monitor_active and ssh_client:
        out, err = exec_cmd("/system resource print")
        monitor_queue.put({"type":"snapshot","time":time.strftime("%H:%M:%S"),"output":out or err})
        time.sleep(interval)

# ── Main ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT_WEB), Handler)
    url = f"http://localhost:{PORT_WEB}"
    print(f"\n  ✔  MANAGEMENT corriendo en {url}")
    print(f"     Backups guardados en: {BACKUP_DIR}")
    print("     Presiona Ctrl+C para detener.\n")
    threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Servidor detenido.")