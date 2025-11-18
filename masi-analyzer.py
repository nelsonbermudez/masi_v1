import socket
import urllib.request
import urllib.error
import json
import subprocess
import re
import csv
from collections import defaultdict
from urllib.parse import urlparse
from datetime import datetime
import sys
import os

# --- Nombres de Archivos y Configuraciones ---
URL_FILENAME = 'url-list1.txt'
JSON_OUTPUT_FILENAME = 'masi_url_analysis.json'
STATS_FILENAME = 'masi_statistics.csv'
FINDINGS_FILENAME = 'new_findings.csv'
BATCH_SIZE = 100
MAX_REDIRECTS = 10 # Define un máximo de redirecciones a registrar

# --- Plantillas para la salida JSON Estandarizada ---
DNS_INFO_TEMPLATE = {
    "status": None,
    "error_message": None,
    "server_name": None,
    "server_address": None,
    "is_authoritative": None,
    "resolved_ips": []
}

# ===== MODIFICACIÓN: Crear dinámicamente la plantilla HTTP con campos de redirección =====
def create_http_info_template():
    template = {
        "status": None,
        "error_message": None,
        "initial_ip_contacted": None,
        "final_status_code": 0,
        "final_server_header": None
    }
    for i in range(1, MAX_REDIRECTS + 1):
        template[f'redirect_{i}_code'] = None
        template[f'redirect_{i}_new_url'] = None
        template[f'redirect_{i}_new_ip'] = None
    return template

HTTP_INFO_TEMPLATE = create_http_info_template()


# --- Lógica para Cancelación Segura (Ctrl+X) ---
EXIT_REQUESTED = False

if os.name == 'nt':
    import msvcrt
else:
    import tty
    import termios
    import select

def check_for_exit():
    """Verifica si se ha presionado Ctrl+X sin bloquear el programa."""
    global EXIT_REQUESTED
    if EXIT_REQUESTED: return

    if os.name == 'nt':
        if msvcrt.kbhit() and msvcrt.getch() == b'\x18':
            EXIT_REQUESTED = True
    else: # POSIX
        if select.select([sys.stdin], [], [], 0) == ([sys.stdin], [], []):
            if sys.stdin.read(1) == '\x18':
                EXIT_REQUESTED = True

# --- Funciones de Análisis ---

def get_public_ip_info():
    try:
        with urllib.request.urlopen('http://ip-api.com/json', timeout=10) as response:
            if response.status == 200:
                data = json.load(response)
                return { "public_ip": data.get('query'), "isp": data.get('isp'), "location": f"{data.get('city', '')}, {data.get('country', '')}" }
    except Exception as e:
        return {"public_ip": None, "isp": None, "location": None, "error": str(e)}
    return {}

def get_dns_info(hostname):
    dns_info = DNS_INFO_TEMPLATE.copy()
    try:
        result = subprocess.run(['nslookup', hostname], capture_output=True, text=True, timeout=10, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        output = result.stdout
        if "can't find" in output or "Non-existent domain" in output:
            dns_info.update({"status": "error", "error_message": f"El dominio '{hostname}' no existe o no se pudo resolver."})
            return dns_info
        
        server = re.search(r"Server:\s*(\S+)", output)
        address = re.search(r"Address:\s*(\S+)", output)
        ips = re.findall(r"Address:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", output)
        server_ip = address.group(1) if address else None
        if server_ip and server_ip in ips: ips.remove(server_ip)
        
        dns_info.update({
            "status": "success",
            "server_name": server.group(1) if server else None,
            "server_address": server_ip,
            "is_authoritative": "Non-authoritative answer" not in output,
            "resolved_ips": ips
        })
    except Exception as e:
        dns_info.update({"status": "error", "error_message": str(e)})
    return dns_info

class RedirectTracker(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        super().__init__()
        self.redirects = []
    def _track_redirect(self, code, headers):
        new_location = headers.get('Location')
        if new_location:
            new_hostname = urlparse(new_location).hostname
            new_ip = None
            if new_hostname:
                try: new_ip = socket.gethostbyname(new_hostname)
                except socket.gaierror: pass
            self.redirects.append({"code": code, "new_url": new_location, "new_ip": new_ip})
    def http_error_301(self, r,f,c,m,h): self._track_redirect(c,h); return super().http_error_301(r,f,c,m,h)
    def http_error_302(self, r,f,c,m,h): self._track_redirect(c,h); return super().http_error_302(r,f,c,m,h)
    def http_error_307(self, r,f,c,m,h): self._track_redirect(c,h); return super().http_error_307(r,f,c,m,h)

def analyze_url_to_json(url, status_counter):
    http_info = HTTP_INFO_TEMPLATE.copy()
    dns_info = get_dns_info(urlparse(url).hostname)
    
    url_result = {"url_analyzed": url, "dns_info": dns_info, "http_info": http_info}

    if dns_info["status"] == "error" or not dns_info.get("resolved_ips"):
        http_info["status"] = "not_attempted"
        return url_result

    target_ip = dns_info['resolved_ips'][0]
    http_info["initial_ip_contacted"] = target_ip
    redirect_tracker = RedirectTracker()
    opener = urllib.request.build_opener(redirect_tracker)
    opener.addheaders = [('User-Agent', 'Python-URL-Analyzer/1.0')]
    
    try:
        response = opener.open(url, timeout=10)
        status_code = response.getcode()
        http_info.update({
            "status": "success",
            "final_status_code": status_code,
            "final_server_header": response.headers.get('Server'),
        })
        status_counter[status_code] += 1
    except urllib.error.HTTPError as e:
        status_counter[e.code] += 1
        http_info.update({
            "status": "error", "error_message": f"Código {e.code} - {e.reason}",
            "final_status_code": e.code, "final_server_header": e.headers.get('Server'),
        })
    except Exception as e:
        status_counter['no_response'] += 1
        http_info.update({"status": "error", "error_message": str(e)})

    # Poblar los campos de redirección que correspondan
    if redirect_tracker.redirects:
        for i, redir in enumerate(redirect_tracker.redirects, 1):
            if i > MAX_REDIRECTS:
                break # No registrar más redirecciones que el máximo definido
            http_info[f'redirect_{i}_code'] = redir.get('code')
            http_info[f'redirect_{i}_new_url'] = redir.get('new_url')
            http_info[f'redirect_{i}_new_ip'] = redir.get('new_ip')
        
    return url_result

def write_output_files(report_data, stats_data, findings_data):
    try:
        with open(JSON_OUTPUT_FILENAME, 'w', encoding='utf-8') as f: json.dump(report_data, f, indent=4, ensure_ascii=False)
    except IOError as e: print(f"\n❌ Error al escribir el archivo JSON: {e}")

    if stats_data:
        try:
            with open(STATS_FILENAME, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['http_code', 'count'])
                for code, count in sorted(stats_data.items(), key=lambda item: str(item[0])): writer.writerow([code, count])
        except IOError as e: print(f"\n❌ Error al escribir el archivo de estadísticas: {e}")
    
    if findings_data:
        try:
            with open(FINDINGS_FILENAME, 'a', newline='', encoding='utf-8') as f:
                csv.writer(f).writerows(findings_data)
        except IOError as e: print(f"\n❌ Error al escribir el archivo de hallazgos: {e}")

# --- Inicio del Script ---
if __name__ == "__main__":
    
    if os.name == 'posix':
        old_settings = termios.tcgetattr(sys.stdin)
    
    try:
        if os.name == 'posix':
            tty.setcbreak(sys.stdin.fileno())

        final_report = {"analysis_metadata": get_public_ip_info(), "results": []}
        
        try:
            with open(URL_FILENAME, 'r') as f: urls = [line.strip() for line in f if line.strip()]
            total_urls = len(urls)
        except FileNotFoundError:
            print(f"❌ Error: El archivo de entrada '{URL_FILENAME}' no fue encontrado."); exit()

        try:
            with open(FINDINGS_FILENAME, 'w', newline='', encoding='utf-8') as f:
                csv.writer(f).writerow(['url', 'ip', 'timestamp'])
        except IOError as e: print(f"❌ No se pudo crear el archivo '{FINDINGS_FILENAME}': {e}"); exit()

        http_status_counts = defaultdict(int)
        batch_findings = []
        
        print(f"🔎 Analizando {total_urls} URLs. Presione Ctrl+X para detener y guardar el progreso.")
        print(f"📝 Se registrará un máximo de {MAX_REDIRECTS} redirecciones por URL.")

        for i, url in enumerate(urls, 1):
            check_for_exit()
            if EXIT_REQUESTED:
                print("\n🛑 Detención solicitada por el usuario. Guardando resultados...")
                break

            print(f"   ({i}/{total_urls}) Procesando: {url}")
            url_to_analyze = 'http://' + url if not url.startswith(('http://', 'https://')) else url
            
            analysis_data = analyze_url_to_json(url_to_analyze, http_status_counts)
            final_report["results"].append(analysis_data)
            
            if analysis_data["dns_info"]["resolved_ips"]:
                timestamp = datetime.now().isoformat()
                for ip in analysis_data["dns_info"]["resolved_ips"]:
                    batch_findings.append([url_to_analyze, ip, timestamp])

            if i % BATCH_SIZE == 0 and i > 0:
                print(f"--- Guardando lote de {BATCH_SIZE} registros... ---")
                write_output_files(final_report, http_status_counts, batch_findings)
                batch_findings.clear()

        # Guardado final
        write_output_files(final_report, http_status_counts, batch_findings)
        
        print(f"\n✅ ¡Análisis completado! Se procesaron {len(final_report['results'])} URLs.")
        print(f"   Reporte JSON guardado en: {JSON_OUTPUT_FILENAME}")
        print(f"   Estadísticas guardadas en: {STATS_FILENAME}")
        print(f"   Hallazgos de IP guardados en: {FINDINGS_FILENAME}")

    finally:
        if os.name == 'posix':
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)