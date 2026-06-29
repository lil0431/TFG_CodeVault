import pyshark
from collections import defaultdict, Counter
from datetime import datetime
import threading
from queue import Queue
import time
import re
import json
import argparse
import os
import requests
import base64

# --- LIBRERÍAS DE REPORTES ---
try:
    import markdown
except ImportError:
    print("[!] Aviso: Librería markdown no instalada. Los PDFs no funcionarán.")

try:
    import pdfkit
except ImportError:
    print("[!] Aviso: Librería pdfkit no instalada. Los PDFs no funcionarán.")

# --- CONFIGURACIÓN DE IA ---
try:
    from google import genai
    from google.genai import types
except ImportError:
    print("[!] Aviso: Librería google-genai no instalada. La IA Gemini no funcionará.")

try:
    from groq import Groq
except ImportError:
    print("[!] Aviso: Librería groq no instalada. Groq no funcionará.")

# ============================================================================
# CONFIGURACIÓN GLOBAL
# ============================================================================

MAX_CONTEXT_CHARS = {
    "gemini": 800_000,
    "groq":   100_000,
}

SEVERITY_BASE = {
    "CRITICAL": 40,
    "HIGH":     25,
    "MEDIUM":   15,
    "LOW":       5,
    "INFO":      2,
}

# ============================================================================
# DICCIONARIOS DE REFERENCIA
# ============================================================================

# Códigos de estado NT (Windows)
NT_STATUS_CODES = {
    '0x00000000': 'SUCCESS ✅',
    '0xc000006d': 'LOGON_FAILURE ❌ (credenciales incorrectas)',
    '0xc0000016': 'MORE_PROCESSING_REQUIRED ⏳ (negociación en curso)',
    '0xc000006e': 'ACCOUNT_RESTRICTION ⛔ (cuenta restringida)',
    '0xc0000064': 'NO_SUCH_USER ❌ (usuario no existe)',
    '0xc000006a': 'WRONG_PASSWORD ❌ (contraseña incorrecta)',
    '0xc0000234': 'ACCOUNT_LOCKED_OUT 🔒 (cuenta bloqueada)',
    '0xc0000193': 'ACCOUNT_EXPIRED ⌛ (cuenta expirada)',
    '0xc0000071': 'PASSWORD_EXPIRED 🔑 (contraseña expirada)',
    '0xc0000072': 'ACCOUNT_DISABLED 🚫 (cuenta deshabilitada)',
    '0xc00000bb': 'NOT_SUPPORTED ⚠️ (operación no soportada)',
    '0xc0000022': 'ACCESS_DENIED 🛑 (acceso denegado)',
}

# Comandos SMB2
SMB2_COMMANDS = {
    '0': 'Negotiate Protocol',
    '1': 'Session Setup',
    '2': 'Logoff',
    '3': 'Tree Connect',
    '4': 'Tree Disconnect',
    '5': 'Create',
    '6': 'Close',
    '7': 'Flush',
    '8': 'Read',
    '9': 'Write',
    '10': 'Lock',
    '11': 'Ioctl',
    '12': 'Cancel',
    '13': 'Echo',
    '14': 'Query Directory',
    '15': 'Change Notify',
    '16': 'Query Info',
    '17': 'Set Info',
    '18': 'Oplock Break',
}

# ============================================================================
# ANALIZADOR MEJORADO
# ============================================================================

class ProTrafficAnalyzer:
    def __init__(self):
        # Protocolos - TODOS
        self.protocols = Counter()
        self.protocols_lock = threading.Lock()
        
        # IPs
        self.ips = set()
        self.ips_lock = threading.Lock()
        
        # Timeline
        self.timeline = []
        self.timeline_lock = threading.Lock()
        
        # Sesiones
        self.sessions = defaultdict(lambda: {
            'packets': 0,
            'protocols': set(),
            'start': None,
            'end': None
        })
        self.sessions_lock = threading.Lock()
        
        # Autenticación
        self.auth_events = []
        self.auth_lock = threading.Lock()
        
        # Credenciales
        self.credentials = []
        self.credentials_lock = threading.Lock()
        
        # Logins exitosos
        self.successful_logins = []
        self.logins_lock = threading.Lock()
        
        # Archivos
        self.file_events = []
        self.file_lock = threading.Lock()
        
        # Detección de ataques
        self.brute_force_attempts = defaultdict(list)
        self.brute_lock = threading.Lock()
        
        # Métricas
        self.total_packets = 0
        self.packets_lock = threading.Lock()
        self.start_time = None
        self.end_time = None
        self.time_lock = threading.Lock()
    
    def analyze_packet(self, packet):
        """Análisis detallado de paquete"""
        try:
            with self.packets_lock:
                self.total_packets += 1
            
            timestamp = packet.sniff_time
            with self.time_lock:
                if not self.start_time:
                    self.start_time = timestamp
                self.end_time = timestamp
            
            # Protocolo COMPLETO
            protocol = self._get_all_protocols(packet)
            
            # IPs
            src_ip = packet.ip.src if hasattr(packet, 'ip') else None
            dst_ip = packet.ip.dst if hasattr(packet, 'ip') else None
            
            # Registrar protocolo
            with self.protocols_lock:
                self.protocols[protocol] += 1
            
            # IPs
            if src_ip:
                with self.ips_lock:
                    self.ips.add(src_ip)
            if dst_ip:
                with self.ips_lock:
                    self.ips.add(dst_ip)
            
            # Info detallada
            info = self._get_detailed_info(packet, protocol)
            
            # Detectar credenciales desde INFO
            self._detect_credentials(packet, protocol, src_ip, dst_ip, timestamp, info)
            
            # Detectar logins exitosos
            self._detect_successful_login(packet, protocol, src_ip, dst_ip, timestamp, info)
            
            # Timeline para eventos importantes
            if self._is_important(protocol, info):
                with self.timeline_lock:
                    self.timeline.append({
                        'time': timestamp,
                        'protocol': protocol,
                        'src': src_ip or 'N/A',
                        'dst': dst_ip or 'N/A',
                        'info': info
                    })
            
            # Sesiones
            if src_ip and dst_ip:
                session_key = f"{src_ip}:{dst_ip}"
                with self.sessions_lock:
                    s = self.sessions[session_key]
                    s['packets'] += 1
                    s['protocols'].add(protocol)
                    if not s['start']:
                        s['start'] = timestamp
                    s['end'] = timestamp
            
            # Detectar patrones
            self._detect_patterns(packet, protocol, info, src_ip, dst_ip, timestamp)
            
        except:
            pass
    
    def _get_all_protocols(self, packet):
        """Obtener TODOS los protocolos - SIN 'OTHER'"""
        # Lista completa de protocolos soportados por Wireshark
        protocols = [
            'smb2', 'smb', 'nbss', 'nbns', 'dcerpc', 'ntlmssp',
            'http', 'https', 'http2', 'ftp', 'ftp-data',
            'ssh', 'telnet', 'dns', 'mdns', 'llmnr',
            'dhcp', 'dhcpv6', 'bootp',
            'arp', 'icmp', 'icmpv6',
            'tcp', 'udp', 'sctp',
            'tls', 'ssl', 'dtls',
            'rdp', 'vnc', 'x11',
            'mysql', 'postgresql', 'mssql', 'oracle',
            'ldap', 'ldaps', 'kerberos',
            'snmp', 'syslog', 'ntp',
            'ssdp', 'upnp', 'soap',
            'pop', 'imap', 'smtp',
            'sip', 'rtp', 'rtcp',
            'igmp', 'ospf', 'bgp',
            'radius', 'tacacs',
            'netbios', 'browser', 'lanman',
            'ip', 'ipv6', 'ipx',
            'eth', 'wlan', 'ppp',
        ]
        
        # Buscar en orden de prioridad (aplicación > transporte > red)
        for proto in protocols:
            if hasattr(packet, proto):
                return proto.upper()
        
        # Si llegamos aquí, buscar en layers
        if hasattr(packet, 'layers'):
            for layer in packet.layers:
                layer_name = layer.layer_name
                if layer_name not in ['frame', 'eth', 'ip', 'tcp', 'udp']:
                    return layer_name.upper()
        
        # Último recurso: transport layer
        if hasattr(packet, 'transport_layer'):
            return packet.transport_layer
        
        return 'UNKNOWN'
    
    def _get_detailed_info(self, packet, protocol):
        """Info DETALLADA con explicaciones"""
        try:
            # SMB2 - COMPLETO
            if protocol == 'SMB2' and hasattr(packet, 'smb2'):
                parts = []
                smb = packet.smb2
                
                # Comando
                if hasattr(smb, 'cmd'):
                    cmd_code = str(smb.cmd)
                    cmd_name = SMB2_COMMANDS.get(cmd_code, f'Command {cmd_code}')
                    parts.append(cmd_name)
                
                # Request/Response
                if hasattr(smb, 'flags_response'):
                    parts.append('Resp' if smb.flags_response == '1' else 'Req')
                
                # Status con explicación
                if hasattr(smb, 'nt_status'):
                    status_code = smb.nt_status.lower()
                    status_desc = NT_STATUS_CODES.get(status_code, f'Status {status_code}')
                    parts.append(status_desc)
                
                # Archivo/recurso
                if hasattr(smb, 'filename'):
                    parts.append(f'File:{smb.filename}')
                
                if hasattr(smb, 'tree'):
                    parts.append(f'Share:{smb.tree}')
                
                return ' '.join(parts)
            
            # NTLMSSP - DETALLADO
            elif protocol == 'NTLMSSP' and hasattr(packet, 'ntlmssp'):
                ntlm = packet.ntlmssp
                if hasattr(ntlm, 'messagetype'):
                    mt = str(ntlm.messagetype)
                    if mt == '1':
                        return 'NEGOTIATE (inicio autenticación)'
                    elif mt == '2':
                        return 'CHALLENGE (servidor envía desafío)'
                    elif mt == '3':
                        user = getattr(ntlm, 'auth_username', '')
                        domain = getattr(ntlm, 'auth_domain', '')
                        full = f'{domain}\\{user}' if domain else user
                        return f'AUTH (intento login con: {full})'
            
            # TCP - Detallado
            elif protocol == 'TCP' and hasattr(packet, 'tcp'):
                tcp = packet.tcp
                flags = []
                if hasattr(tcp, 'flags_syn') and tcp.flags_syn == '1':
                    flags.append('SYN')
                if hasattr(tcp, 'flags_ack') and tcp.flags_ack == '1':
                    flags.append('ACK')
                if hasattr(tcp, 'flags_fin') and tcp.flags_fin == '1':
                    flags.append('FIN')
                if hasattr(tcp, 'flags_reset') and tcp.flags_reset == '1':
                    flags.append('RST')
                
                info_parts = []
                if flags:
                    info_parts.append(f"[{','.join(flags)}]")
                
                if hasattr(tcp, 'srcport') and hasattr(tcp, 'dstport'):
                    info_parts.append(f"Port {tcp.srcport}→{tcp.dstport}")
                
                return ' '.join(info_parts)
            
            # ICMP
            elif protocol == 'ICMP' and hasattr(packet, 'icmp'):
                t = str(getattr(packet.icmp, 'type', ''))
                types = {
                    '8': 'Echo Request (Ping)',
                    '0': 'Echo Reply (Pong)',
                    '3': 'Destination Unreachable',
                    '11': 'Time Exceeded'
                }
                return types.get(t, f'Type {t}')
            
            # ARP
            elif protocol == 'ARP' and hasattr(packet, 'arp'):
                arp = packet.arp
                if hasattr(arp, 'opcode'):
                    if arp.opcode == '1':
                        return f"Who has {getattr(arp, 'dst_proto_ipv4', '?')}?"
                    elif arp.opcode == '2':
                        return f"{getattr(arp, 'src_proto_ipv4', '?')} is at {getattr(arp, 'src_hw_mac', '?')}"
            
            # DNS
            elif protocol == 'DNS' and hasattr(packet, 'dns'):
                dns = packet.dns
                if hasattr(dns, 'qry_name'):
                    qtype = 'Query' if getattr(dns, 'flags_response', '0') == '0' else 'Response'
                    return f"{qtype}: {dns.qry_name}"
            
        except:
            pass
        
        return ''
    
    def _detect_credentials(self, packet, protocol, src_ip, dst_ip, timestamp, info):
        """Detectar credenciales de TODOS los protocolos - MEJORADO"""
        try:
            # ═══ DETECCIÓN ESPECÍFICA POR PROTOCOLO ═══
            
            # HTTP / HTTPS - Authorization headers
            if protocol in ['HTTP', 'HTTPS'] and hasattr(packet, 'http'):
                http = packet.http
                
                # Basic Auth
                if hasattr(http, 'authorization'):
                    auth = str(http.authorization)
                    if auth.startswith('Basic '):
                        try:
                            decoded = base64.b64decode(auth[6:]).decode('utf-8', errors='ignore')
                            if ':' in decoded:
                                user, pwd = decoded.split(':', 1)
                                with self.credentials_lock:
                                    self.credentials.append({
                                        'time': timestamp, 'protocol': 'HTTP_BASIC',
                                        'type': 'credentials', 'value': f'{user}:{pwd}',
                                        'src': src_ip, 'dst': dst_ip, 'field': 'http.authorization'
                                    })
                        except:
                            pass
                
                # Cookies que contienen tokens/sesiones
                if hasattr(http, 'cookie'):
                    cookie = str(http.cookie)
                    with self.credentials_lock:
                        self.credentials.append({
                            'time': timestamp, 'protocol': 'HTTP_COOKIE',
                            'type': 'session_token', 'value': cookie[:100],
                            'src': src_ip, 'dst': dst_ip, 'field': 'http.cookie'
                        })
            
            # FTP
            if protocol == 'FTP' and hasattr(packet, 'ftp'):
                ftp = packet.ftp
                if hasattr(ftp, 'request_command'):
                    cmd = str(ftp.request_command)
                    if cmd.upper() == 'USER' and hasattr(ftp, 'request_arg'):
                        with self.credentials_lock:
                            self.credentials.append({
                                'time': timestamp, 'protocol': 'FTP',
                                'type': 'username', 'value': str(ftp.request_arg),
                                'src': src_ip, 'dst': dst_ip, 'field': 'ftp.request.arg'
                            })
                    elif cmd.upper() == 'PASS' and hasattr(ftp, 'request_arg'):
                        with self.credentials_lock:
                            self.credentials.append({
                                'time': timestamp, 'protocol': 'FTP',
                                'type': 'password', 'value': str(ftp.request_arg),
                                'src': src_ip, 'dst': dst_ip, 'field': 'ftp.request.arg'
                            })
            
            # NTLMSSP (Windows Auth)
            if hasattr(packet, 'ntlmssp'):
                ntlm = packet.ntlmssp
                if hasattr(ntlm, 'auth_username'):
                    username = str(ntlm.auth_username)
                    if username and username != '0':
                        with self.credentials_lock:
                            self.credentials.append({
                                'time': timestamp, 'protocol': 'NTLMSSP',
                                'type': 'username', 'value': username,
                                'src': src_ip, 'dst': dst_ip, 'field': 'ntlmssp.auth.username'
                            })
                
                if hasattr(ntlm, 'auth_domain'):
                    domain = str(ntlm.auth_domain)
                    if domain and domain != '0':
                        with self.credentials_lock:
                            self.credentials.append({
                                'time': timestamp, 'protocol': 'NTLMSSP',
                                'type': 'domain', 'value': domain,
                                'src': src_ip, 'dst': dst_ip, 'field': 'ntlmssp.auth.domain'
                            })
            
            # LDAP (Active Directory)
            if protocol == 'LDAP' and hasattr(packet, 'ldap'):
                ldap = packet.ldap
                if hasattr(ldap, 'simple_bind_dn'):
                    with self.credentials_lock:
                        self.credentials.append({
                            'time': timestamp, 'protocol': 'LDAP',
                            'type': 'dn', 'value': str(ldap.simple_bind_dn),
                            'src': src_ip, 'dst': dst_ip, 'field': 'ldap.simple_bind.dn'
                        })
            
            # ═══ BÚSQUEDA GENÉRICA EN PAYLOAD ═══
            
            # Buscar en cuerpo de HTTP (JSON, formularios, etc)
            if hasattr(packet, 'http') and hasattr(packet.http, 'file_data'):
                try:
                    payload = str(packet.http.file_data)
                    
                    # Patrones JSON comunes
                    json_patterns = [
                        (r'"username"\s*:\s*"([^"]+)"', 'username'),
                        (r'"user"\s*:\s*"([^"]+)"', 'username'),
                        (r'"email"\s*:\s*"([^"]+)"', 'email'),
                        (r'"password"\s*:\s*"([^"]+)"', 'password'),
                        (r'"pass"\s*:\s*"([^"]+)"', 'password'),
                        (r'"token"\s*:\s*"([^"]+)"', 'token'),
                        (r'"apikey"\s*:\s*"([^"]+)"', 'apikey'),
                    ]
                    
                    for pattern, cred_type in json_patterns:
                        matches = re.findall(pattern, payload, re.IGNORECASE)
                        for match in matches:
                            if match and len(match) > 2:
                                with self.credentials_lock:
                                    self.credentials.append({
                                        'time': timestamp, 'protocol': 'HTTP_PAYLOAD',
                                        'type': cred_type, 'value': match,
                                        'src': src_ip, 'dst': dst_ip, 'field': 'http.file_data'
                                    })
                except:
                    pass
        
        except:
            pass
    
    def _detect_successful_login(self, packet, protocol, src_ip, dst_ip, timestamp, info):
        """Detectar logins exitosos"""
        try:
            # SMB2 Session Setup con SUCCESS
            if protocol == 'SMB2' and hasattr(packet, 'smb2'):
                smb = packet.smb2
                if hasattr(smb, 'cmd') and smb.cmd == '1':  # Session Setup
                    if hasattr(smb, 'nt_status') and smb.nt_status == '0x00000000':
                        if hasattr(smb, 'flags_response') and smb.flags_response == '1':
                            # Buscar credenciales usadas
                            username = None
                            for cred in reversed(self.credentials):
                                if cred['src'] == src_ip and cred['type'] == 'username':
                                    username = cred['value']
                                    break
                            
                            with self.logins_lock:
                                self.successful_logins.append({
                                    'time': timestamp,
                                    'protocol': 'SMB2',
                                    'src': src_ip,
                                    'dst': dst_ip,
                                    'username': username
                                })
            
            # FTP 230 (User logged in)
            if hasattr(packet, 'ftp'):
                ftp = packet.ftp
                if hasattr(ftp, 'response_code'):
                    if ftp.response_code == '230':
                        # Buscar credenciales
                        username = None
                        password = None
                        for cred in reversed(self.credentials):
                            if cred['src'] == dst_ip:  # Cliente es dst en respuesta
                                if cred['type'] == 'username' and not username:
                                    username = cred['value']
                                elif cred['type'] == 'password' and not password:
                                    password = cred['value']
                                
                                if username and password:
                                    break
                        
                        with self.logins_lock:
                            self.successful_logins.append({
                                'time': timestamp,
                                'protocol': 'FTP',
                                'src': dst_ip,  # Invertir porque es respuesta
                                'dst': src_ip,
                                'username': username,
                                'password': password
                            })
        except:
            pass
    
    def _is_important(self, protocol, info):
        """Filtrar eventos importantes"""
        important_protocols = ['SMB2', 'NTLMSSP', 'HTTP', 'FTP', 'SSH', 'DNS', 'DHCP']
        
        if protocol in important_protocols:
            return True
        
        if protocol == 'TCP' and 'SYN' in info and 'ACK' not in info:
            return True
        
        return False
    
    def _detect_patterns(self, packet, protocol, info, src_ip, dst_ip, timestamp):
        """Detectar patrones de ataque"""
        info_lower = info.lower()
        
        # Autenticación
        if any(w in info_lower for w in ['auth', 'login', 'session setup', 'negotiate']):
            with self.auth_lock:
                self.auth_events.append({
                    'time': timestamp,
                    'src': src_ip,
                    'dst': dst_ip,
                    'protocol': protocol,
                    'info': info
                })
            
            # Detectar brute force
            if any(w in info_lower for w in ['failure', 'logon_failure', '0xc000006d', 'denied', 'incorrect', 'failed', 'invalid']):
                # Buscar TODAS las credenciales recientes relacionadas (últimos 5 segundos)
                attempted_user = None
                attempted_pass = None
                attempted_domain = None
                
                with self.credentials_lock:
                    for cred in reversed(self.credentials):
                        time_diff = (timestamp - cred['time']).total_seconds()
                        if time_diff <= 5 and cred['src'] == src_ip:
                            if cred['type'] == 'username' and not attempted_user:
                                attempted_user = cred['value']
                            elif cred['type'] == 'password' and not attempted_pass:
                                attempted_pass = cred['value']
                            elif cred['type'] == 'domain' and not attempted_domain:
                                attempted_domain = cred['value']
                        
                        # Si ya tenemos todo, salir
                        if attempted_user and attempted_pass:
                            break
                
                # Formatear usuario completo
                full_user = attempted_user
                if attempted_domain and attempted_user:
                    full_user = f"{attempted_domain}\\{attempted_user}"
                
                with self.brute_lock:
                    self.brute_force_attempts[src_ip].append({
                        'time': timestamp,
                        'username': full_user,
                        'password': attempted_pass,
                        'info': info,
                        'protocol': protocol
                    })
        
        # Archivos
        if any(w in info_lower for w in ['file:', 'create', 'open', 'read', 'write']):
            with self.file_lock:
                self.file_events.append({
                    'time': timestamp,
                    'src': src_ip,
                    'dst': dst_ip,
                    'protocol': protocol,
                    'info': info
                })
    
    def generate_report(self):
        """Reporte estructurado PRO"""
        lines = []
        
        lines.append("=" * 80)
        lines.append("📊 ANÁLISIS PROFESIONAL DE TRÁFICO")
        lines.append("=" * 80)
        
        # Métricas
        duration = (self.end_time - self.start_time).total_seconds() if self.start_time else 0
        
        lines.append(f"\n⏱️  VENTANA DE CAPTURA:")
        lines.append(f"   • Inicio:    {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"   • Fin:       {self.end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"   • Duración:  {duration:.1f}s ({duration/60:.1f} min)")
        
        lines.append(f"\n📦 ESTADÍSTICAS DE PAQUETES:")
        lines.append(f"   • Total procesados:  {self.total_packets:,}")
        lines.append(f"   • Velocidad promedio: {self.total_packets/duration:.0f} paq/s" if duration > 0 else "")
        
        lines.append(f"\n🌐 DIRECCIONES IP DETECTADAS: {len(self.ips)}")
        for ip in sorted(list(self.ips))[:15]:
            # Contar actividad por IP
            ip_activity = sum(1 for s in self.sessions if ip in s)
            lines.append(f"   • {ip:<16} ({ip_activity} sesiones)")
        
        lines.append(f"\n📡 PROTOCOLOS DETECTADOS: {len(self.protocols)} tipos")
        lines.append(f"\n   {'Protocolo':<15} {'Paquetes':>10}  {'%':>6}  Descripción")
        lines.append(f"   {'-'*15} {'-'*10}  {'-'*6}  {'-'*30}")
        
        proto_descriptions = {
            'SMB2': 'Compartición archivos Windows',
            'SMB': 'Compartición archivos (versión antigua)',
            'NTLMSSP': 'Autenticación Windows',
            'TCP': 'Protocolo de transporte',
            'UDP': 'Protocolo de transporte sin conexión',
            'ICMP': 'Ping y diagnóstico',
            'IGMP': 'Gestión de grupos multicast',
            'ARP': 'Resolución direcciones MAC',
            'NBNS': 'Resolución nombres NetBIOS',
            'LLMNR': 'Resolución nombres local (Link-Local)',
            'MDNS': 'Multicast DNS (Bonjour/Avahi)',
            'DNS': 'Resolución nombres dominio',
            'DHCP': 'Asignación automática de IPs',
            'HTTP': 'Navegación web',
            'HTTPS': 'Navegación web segura',
            'FTP': 'Transferencia archivos',
            'SSH': 'Acceso remoto seguro',
            'TELNET': 'Acceso remoto (inseguro)',
            'DCERPC': 'RPC distribuido Microsoft',
            'RDP': 'Escritorio remoto Windows',
            'LDAP': 'Directorio Active Directory',
            'KERBEROS': 'Autenticación de red',
            'TLS': 'Cifrado de capa de transporte',
            'SSL': 'Capa de sockets seguros',
            'NETBIOS': 'Servicio de nombres de red',
            'BROWSER': 'Navegador de red Windows',
        }
        
        for proto, count in self.protocols.most_common(20):
            pct = (count/self.total_packets*100) if self.total_packets else 0
            desc = proto_descriptions.get(proto, '')
            lines.append(f"   {proto:<15} {count:>10,}  {pct:>5.1f}%  {desc}")
        
        # CREDENCIALES EN CLARO
        if self.credentials:
            lines.append(f"\n🔓 CREDENCIALES TRANSMITIDAS EN CLARO: {len(self.credentials)}")
            lines.append("   ⚠️  ALERTA DE SEGURIDAD CRÍTICA")
            
            # Mostrar CADA intento de credencial con detalles
            for cred in self.credentials:
                t = cred['time'].strftime('%H:%M:%S')
                tipo = '👤 Usuario' if cred['type'] == 'username' else '🔑 Contraseña'
                lines.append(f"\n   {t} | {cred['protocol']:<12} | {tipo}")
                lines.append(f"      {cred['src']:15} → {cred['dst']:15}")
                lines.append(f"      Valor: {cred['value']}")
        
        # LOGINS EXITOSOS
        if self.successful_logins:
            lines.append(f"\n✅ LOGINS EXITOSOS: {len(self.successful_logins)}")
            for login in self.successful_logins:
                t = login['time'].strftime('%H:%M:%S')
                user = login.get('username', 'N/A')
                pwd = login.get('password', '')
                
                lines.append(f"   • {t} {login['protocol']:<10} {login['src']:15} → {login['dst']:15}")
                lines.append(f"      Usuario: {user}")
                if pwd:
                    lines.append(f"      Contraseña: {pwd} ⚠️  COMPROMETIDA")
        
        # AUTENTICACIONES
        if self.auth_events:
            lines.append(f"\n🔐 EVENTOS DE AUTENTICACIÓN: {len(self.auth_events)}")
            for auth in self.auth_events[:15]:
                t = auth['time'].strftime('%H:%M:%S')
                lines.append(f"   • {t} {auth['src']:15} → {auth['dst']:15} {auth['info']}")
        
        # BRUTE FORCE
        if self.brute_force_attempts:
            lines.append(f"\n🚨 DETECCIÓN DE ATAQUES DE FUERZA BRUTA:")
            for ip, attempts in self.brute_force_attempts.items():
                if len(attempts) >= 3:
                    lines.append(f"\n   Origen: {ip} - {len(attempts)} intentos fallidos")
                    lines.append(f"   {'Hora':<12} {'Protocolo':<12} {'Credenciales Intentadas':<40} Resultado")
                    lines.append(f"   {'-'*12} {'-'*12} {'-'*40} {'-'*30}")
                    
                    for attempt in attempts:
                        t = attempt['time'].strftime('%H:%M:%S')
                        proto = attempt.get('protocol', 'N/A')
                        user = attempt.get('username') or 'N/A'
                        pwd = attempt.get('password')
                        
                        # Formatear credenciales
                        if pwd:
                            creds = f"👤 {user} / 🔑 {pwd}"
                        else:
                            creds = f"👤 {user}"
                        
                        # Resultado corto
                        info_short = attempt['info'][:30] if attempt['info'] else ''
                        
                        lines.append(f"   {t:<12} {proto:<12} {creds:<40} {info_short}")
        
        # ARCHIVOS
        if self.file_events:
            lines.append(f"\n📁 OPERACIONES CON ARCHIVOS: {len(self.file_events)}")
            
            # Extraer nombres de archivos
            files = []
            for fe in self.file_events:
                match = re.search(r'[Ff]ile:(\S+)', fe['info'])
                if match:
                    files.append(match.group(1))
            
            unique_files = list(set(files))
            if unique_files:
                lines.append(f"\n   Archivos accedidos:")
                for f in unique_files[:20]:
                    lines.append(f"      • {f}")
        
        lines.append("\n" + "=" * 80)
        return "\n".join(lines)
    
    def generate_recommendations(self):
        """Generar recomendaciones de seguridad"""
        recs = []
        
        recs.append("=" * 80)
        recs.append("💡 RECOMENDACIONES DE SEGURIDAD")
        recs.append("=" * 80)
        
        # Credenciales en claro
        if self.credentials:
            recs.append("\n🔴 CRÍTICO - Credenciales en texto plano detectadas:")
            
            protocols_insecure = set(c['protocol'] for c in self.credentials)
            
            for proto in protocols_insecure:
                if 'FTP' in proto:
                    recs.append("   • Migrar de FTP a SFTP o FTPS inmediatamente")
                    recs.append("     Comando: sudo apt install vsftpd; configurar SSL/TLS")
                
                if 'HTTP' in proto:
                    recs.append("   • Implementar HTTPS con certificado SSL/TLS")
                    recs.append("     Herramienta: Let's Encrypt (certbot)")
                
                if 'NTLMSSP' in proto or 'SMB' in proto:
                    recs.append("   • Configurar cifrado SMB3 obligatorio")
                    recs.append("     GPO: Computer Configuration → Administrative Templates → Network → Lanman Server")
        
        # Logins exitosos
        if self.successful_logins:
            recs.append("\n🟡 URGENTE - Logins exitosos con credenciales comprometidas:")
            
            compromised = set()
            for login in self.successful_logins:
                if login.get('username'):
                    compromised.add(login['username'])
            
            if compromised:
                recs.append(f"   • Cambiar INMEDIATAMENTE las siguientes credenciales:")
                for user in compromised:
                    recs.append(f"      - {user}")
                
                recs.append("   • Implementar autenticación multifactor (MFA)")
                recs.append("   • Auditar logs para verificar accesos no autorizados")
        
        # Brute force
        if self.brute_force_attempts:
            recs.append("\n🟠 ATENCIÓN - Ataques de fuerza bruta detectados:")
            
            for ip, attempts in self.brute_force_attempts.items():
                if len(attempts) >= 3:
                    recs.append(f"   • Bloquear IP {ip} en firewall")
            
            recs.append("   • Implementar fail2ban o similar")
            recs.append("   • Configurar límites de intentos de login")
        
        # Protocolos inseguros
        insecure_protocols = {'FTP', 'HTTP', 'TELNET', 'SMB'}
        detected_insecure = insecure_protocols & set(self.protocols.keys())
        
        if detected_insecure:
            recs.append("\n🟢 MEJORAS GENERALES - Protocolos inseguros en uso:")
            for proto in detected_insecure:
                recs.append(f"   • {proto} detectado - considerar alternativa segura")
        
        recs.append("\n" + "=" * 80)
        return "\n".join(recs)


# ============================================================================
# FASE 2b: RISK SCORING (ENRIQUECIMIENTO CON NIST NVD)
# ============================================================================

class RiskScorer:
    """Puntúa hallazgos de seguridad basado en patrones y severidad"""
    
    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    _cvss_cache: dict = {}

    def _fetch_cvss_for_cwe(self, cwe_id: str) -> float:
        """Obtiene CVSS promedio del CWE desde NIST NVD"""
        if not cwe_id or not cwe_id.startswith("CWE-"):
            return 0.0
        if cwe_id in self._cvss_cache:
            return self._cvss_cache[cwe_id]

        try:
            params = {
                "cweId": cwe_id,
                "resultsPerPage": 10,
                "startIndex": 0,
            }
            r = requests.get(self.NVD_API, params=params, timeout=5)
            if r.status_code != 200:
                return 0.0

            data = r.json()
            items = data.get("vulnerabilities", [])
            scores = []
            for item in items:
                try:
                    metrics = item.get("cve", {}).get("metrics", {})
                    cvss_v3 = metrics.get("cvssMetricV31", [{}])[0] if metrics.get("cvssMetricV31") else {}
                    score = float(cvss_v3.get("cvssData", {}).get("baseScore", 0))
                    if score > 0:
                        scores.append(score)
                except:
                    pass

            avg = round(sum(scores) / len(scores), 2) if scores else 0.0
            self._cvss_cache[cwe_id] = avg
            time.sleep(0.2)
            return avg

        except Exception:
            self._cvss_cache[cwe_id] = 0.0
            return 0.0

    def score(self, findings: list) -> list:
        """Puntúa hallazgos y devuelve lista ordenada"""
        print("[*] FASE 2b: Calculando Risk Scores (enriquecido con NIST NVD)...")

        # Agrupar por tipo de ataque
        finding_groups = defaultdict(list)
        for f in findings:
            finding_groups[f["tipo"]].append(f)

        scored = []
        for finding_type, hits in finding_groups.items():
            sev = self._get_severity(finding_type)
            base_pts = SEVERITY_BASE.get(sev, 15)
            
            # Intentar obtener CVSS
            cwe = self._get_cwe_for_type(finding_type)
            cvss = self._fetch_cvss_for_cwe(cwe) if cwe else 0.0
            nvd_pts = round(cvss * 3, 1) if cvss > 0 else 0

            total_score = min(100, base_pts + nvd_pts + len(hits) * 2)

            scored.append({
                "tipo": finding_type,
                "count": len(hits),
                "score": total_score,
                "nivel": _score_to_level_traffic(total_score),
                "severidad": sev,
                "cwe": cwe,
                "cvss_nvd": cvss,
            })

        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored

    def _get_severity(self, finding_type: str) -> str:
        """Mapea tipo de hallazgo a severidad"""
        high_severity = {
            "BRUTE_FORCE": "HIGH",
            "CREDENTIALS_CLEARTEXT": "CRITICAL",
            "SUCCESSFUL_COMPROMISE": "CRITICAL",
            "DATA_EXFILTRATION": "CRITICAL",
            "C2_COMMUNICATION": "HIGH",
        }
        return high_severity.get(finding_type, "MEDIUM")

    def _get_cwe_for_type(self, finding_type: str) -> str:
        """Mapea tipo de hallazgo a CWE"""
        mapping = {
            "BRUTE_FORCE": "CWE-307",
            "CREDENTIALS_CLEARTEXT": "CWE-312",
            "WEAK_AUTH": "CWE-521",
            "LATERAL_MOVEMENT": "CWE-863",
            "DATA_EXFILTRATION": "CWE-522",
        }
        return mapping.get(finding_type, "")


def _score_to_level_traffic(score: float) -> str:
    """Convierte score a nivel de severidad para tráfico"""
    if score >= 70:
        return "CRÍTICO"
    if score >= 45:
        return "ALTO"
    if score >= 20:
        return "MEDIO"
    if score > 0:
        return "BAJO"
    return "INFO"


# ============================================================================
# FASE 3: ANÁLISIS IA DINÁMICA
# ============================================================================

class AIAnalyzer:
    def __init__(self, api_key, engine="gemini"):
        self.engine = engine
        self.api_key = api_key

        if engine == "gemini":
            self.client = genai.Client(api_key=api_key)
        elif engine == "groq":
            self.client = Groq(api_key=api_key)

    def _build_prompt(self, analyzer, scored_findings, args):
        """Construye prompt para análisis IA del tráfico"""
        prompt = """
Eres un analista experto en seguridad de redes y tráfico malicioso.

Tu objetivo es analizar el tráfico de red capturado y proporcionar:

1. INTERPRETACIÓN: Explicar qué está pasando en la red como si le enseñaras a otro analista
2. CONTEXTO: Por qué estos hallazgos son importantes
3. RELACIÓN: Cómo se conectan los eventos entre sí
4. IMPACTO: Qué riesgo real representa

NO generes listas genéricas. Habla como un investigador real.

Prioriza:
- Hallazgos críticos
- Patrones de ataque
- Credenciales comprometidas
- Indicadores de Compromise (IoCs)
- Recomendaciones prácticas

Responde en Markdown técnico y didáctico.
"""

        if args.get("explain"):
            prompt += """

## EXPLICACIÓN DEL TRÁFICO

Explica el flujo de la red paso a paso:
- Qué protocolos se usan
- Quiénes son los actores (IPs)
- Qué patrones de comunicación hay
- Qué es sospechoso y por qué
"""

        if args.get("ai_vulns"):
            prompt += """

## VULNERABILIDADES Y ATAQUES

Analiza qué se está explotando:
- Credenciales en texto plano (qué impacto tiene)
- Ataques de fuerza bruta (capacidad real)
- Acceso no autorizado (qué se puede hacer)
- Movimiento lateral (cómo se propaga)
"""

        if args.get("mitigate"):
            prompt += """

## MITIGACIONES Y DEFENSA

Explica cómo defenderse:
- Qué controles se necesitan
- Cómo detectar esto en el futuro
- Qué herramientas ayudarían
- Configuración de seguridad recomendada
"""

        # Añadir datos del análisis
        data_summary = {
            "total_packets": analyzer.total_packets,
            "ip_count": len(analyzer.ips),
            "protocols": dict(analyzer.protocols.most_common(10)),
            "auth_events": len(analyzer.auth_events),
            "credentials_found": len(analyzer.credentials),
            "successful_logins": len(analyzer.successful_logins),
            "brute_force_ips": list(analyzer.brute_force_attempts.keys()),
            "top_findings": scored_findings[:5] if scored_findings else [],
        }

        prompt += f"\n\n## DATOS ANALIZADOS\n```json\n{json.dumps(data_summary, indent=2)}\n```"

        return prompt

    def analyze(self, analyzer, scored_findings, args):
        """Consulta IA para análisis complementario"""
        print(f"[*] FASE 3: Consultando IA ({self.engine.upper()})...")
        prompt = self._build_prompt(analyzer, scored_findings, args)

        try:
            if self.engine == "gemini":
                response = self.client.models.generate_content(
                    model="gemini-2.5-flash",
                    contents=prompt,
                    config=types.GenerateContentConfig(temperature=0.3)
                )
                return response.text

            elif self.engine == "groq":
                response = self.client.chat.completions.create(
                    model="mixtral-8x7b-32768",
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.3,
                    max_tokens=2048,
                )
                return response.choices[0].message.content
        except Exception as e:
            print(f"[!] Error en análisis IA: {e}")
            return ""


# ============================================================================
# FASE 4: GENERADOR DE REPORTES
# ============================================================================

# ============================================================================
# FASE 4: GENERADOR DE REPORTES
# ============================================================================

class ReportGenerator:
    @staticmethod
    def _serialize_datetime(obj):
        """Convierte datetime a string recursivamente"""
        if isinstance(obj, dict):
            return {k: ReportGenerator._serialize_datetime(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [ReportGenerator._serialize_datetime(item) for item in obj]
        elif isinstance(obj, datetime):
            return obj.isoformat()
        return obj

    @staticmethod
    def _level_badge(level: str) -> str:
        """Genera badge HTML para nivel de severidad (estilo CodeVault)"""
        styles = {
            "CRÍTICO": "background:#fee2e2;color:#7f1d1d;border:1px solid #fca5a5;",
            "ALTO":    "background:#ffedd5;color:#7c2d12;border:1px solid #fdba74;",
            "MEDIO":   "background:#fef9c3;color:#713f12;border:1px solid #fde047;",
            "BAJO":    "background:#dcfce7;color:#14532d;border:1px solid #86efac;",
            "INFO":    "background:#f1f5f9;color:#475569;border:1px solid #cbd5e1;",
        }
        style = styles.get(level, styles["INFO"])
        return (f'<span style="{style}padding:4px 12px;border-radius:4px;'
                f'font-size:12px;font-weight:700;letter-spacing:0.04em;">{level}</span>')

    @staticmethod
    def create_json_report(analyzer, scored_findings, ai_report, output_file):
        """Genera reporte completo en JSON"""
        print(f"[*] Generando reporte JSON ({output_file})...")

        report_data = {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "total_packets": analyzer.total_packets,
                "duration_seconds": (analyzer.end_time - analyzer.start_time).total_seconds() if analyzer.start_time else 0,
                "ips_detected": len(analyzer.ips),
                "protocols": dict(analyzer.protocols.most_common(20)),
            },
            "security_findings": {
                "risk_scores": scored_findings,
                "credentials": ReportGenerator._serialize_datetime(analyzer.credentials),
                "successful_logins": ReportGenerator._serialize_datetime(analyzer.successful_logins),
                "brute_force_attempts": ReportGenerator._serialize_datetime(dict(analyzer.brute_force_attempts)),
                "auth_events": ReportGenerator._serialize_datetime(analyzer.auth_events[:50]),
            },
            "ai_analysis": ai_report,
            "timeline": [
                {
                    "time": str(e["time"]),
                    "protocol": e["protocol"],
                    "src": e["src"],
                    "dst": e["dst"],
                    "info": e["info"],
                }
                for e in analyzer.timeline[:100]
            ],
        }

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)

        print(f"[+] JSON guardado en: {output_file}")

    @staticmethod
    def create_pdf_report(analyzer, scored_findings, ai_report, output_name):
        """Genera reporte en PDF con estilo CodeVault"""
        print(f"[*] Generando PDF ({output_name}.pdf)...")

        # ── CSS ────────────────────────────────────────────────────────────────
        css = """
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: #f8fafc;
                color: #1e293b;
                line-height: 1.6;
            }
            .container { max-width: 900px; margin: 0 auto; padding: 20px; background: white; }
            
            /* Portada */
            .cover {
                background: linear-gradient(135deg, #3b82f6 0%, #1e40af 100%);
                color: white;
                padding: 80px 40px;
                text-align: center;
                border-radius: 8px;
                margin-bottom: 40px;
            }
            .cover h1 { font-size: 48px; margin-bottom: 20px; }
            .cover p { font-size: 18px; opacity: 0.9; }
            
            /* Títulos */
            h1 { color: #1e293b; font-size: 32px; margin-top: 40px; margin-bottom: 20px; border-bottom: 2px solid #3b82f6; padding-bottom: 10px; }
            h2 { color: #1e40af; font-size: 24px; margin-top: 30px; margin-bottom: 15px; }
            h3 { color: #475569; font-size: 18px; margin-top: 20px; margin-bottom: 10px; }
            
            /* Tablas */
            table {
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
                background: #f8fafc;
            }
            th {
                background: #3b82f6;
                color: white;
                padding: 12px;
                text-align: left;
                font-weight: 600;
            }
            td {
                padding: 12px;
                border-bottom: 1px solid #bfdbfe;
            }
            tr:hover { background: #f0f6ff; }
            
            /* Badges */
            .badge {
                display: inline-block;
                padding: 4px 12px;
                border-radius: 4px;
                font-size: 12px;
                font-weight: 700;
            }
            .badge-critico { background: #fee2e2; color: #7f1d1d; border: 1px solid #fca5a5; }
            .badge-alto { background: #ffedd5; color: #7c2d12; border: 1px solid #fdba74; }
            .badge-medio { background: #fef9c3; color: #713f12; border: 1px solid #fde047; }
            .badge-bajo { background: #dcfce7; color: #14532d; border: 1px solid #86efac; }
            .badge-info { background: #f1f5f9; color: #475569; border: 1px solid #cbd5e1; }
            
            /* Alertas */
            .alert {
                padding: 16px;
                border-radius: 6px;
                margin: 20px 0;
                border-left: 4px solid;
            }
            .alert-critical { background: #fee2e2; border-color: #dc2626; color: #7f1d1d; }
            .alert-warning { background: #fef9c3; border-color: #eab308; color: #713f12; }
            .alert-info { background: #dbeafe; border-color: #3b82f6; color: #1e40af; }
            
            /* Código */
            pre {
                background: #1e293b;
                color: #e2e8f0;
                padding: 16px;
                border-radius: 6px;
                overflow-x: auto;
                margin: 15px 0;
                font-size: 12px;
            }
            code { font-family: 'Courier New', monospace; }
            
            /* Otros */
            .metric { display: inline-block; margin: 10px 20px 10px 0; }
            .metric-value { font-size: 24px; font-weight: 700; color: #3b82f6; }
            .metric-label { font-size: 12px; color: #64748b; }
            .divider { height: 1px; background: #bfdbfe; margin: 30px 0; }
            .page-break { page-break-after: always; }
        </style>
        """

        # ── PORTADA ────────────────────────────────────────────────────────────
        duration = (analyzer.end_time - analyzer.start_time).total_seconds() if analyzer.start_time else 0
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Análisis PCAP - {output_name}</title>
            {css}
        </head>
        <body>
        <div class="container">
            <div class="cover">
                <h1>📊 ANÁLISIS DE TRÁFICO PCAP</h1>
                <p>Reporte de Seguridad Profesional</p>
                <div style="margin-top: 30px; font-size: 14px;">
                    <div>{timestamp}</div>
                    <div>{analyzer.total_packets:,} paquetes analizados</div>
                </div>
            </div>

            <h1>📈 Resumen Ejecutivo</h1>
            <div class="alert alert-info">
                <strong>Análisis completado exitosamente</strong> - Se han analizado {analyzer.total_packets:,} paquetes 
                en {duration:.1f} segundos ({duration/60:.1f} minutos). Se han detectado {len(analyzer.ips)} IPs únicas 
                utilizando {len(analyzer.protocols)} protocolos diferentes.
            </div>

            <div style="display: grid; grid-template-columns: 1fr 1fr 1fr 1fr; gap: 15px; margin: 20px 0;">
                <div class="metric">
                    <div class="metric-value">{analyzer.total_packets:,}</div>
                    <div class="metric-label">Paquetes</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{len(analyzer.ips)}</div>
                    <div class="metric-label">IPs Detectadas</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{len(analyzer.credentials)}</div>
                    <div class="metric-label">Credenciales</div>
                </div>
                <div class="metric">
                    <div class="metric-value">{len(analyzer.successful_logins)}</div>
                    <div class="metric-label">Logins Exitosos</div>
                </div>
            </div>

            <div class="divider"></div>

            <!-- RISK SCORES -->
            <h1>🎯 Risk Scores</h1>
            {ReportGenerator._generate_risk_scores_html(scored_findings)}

            <!-- CREDENCIALES -->
            {ReportGenerator._generate_credentials_html(analyzer.credentials)}

            <!-- LOGINS EXITOSOS -->
            {ReportGenerator._generate_successful_logins_html(analyzer.successful_logins)}

            <!-- BRUTE FORCE -->
            {ReportGenerator._generate_brute_force_html(analyzer.brute_force_attempts)}

            <!-- PROTOCOLOS -->
            <h1>🌐 Protocolos Detectados</h1>
            {ReportGenerator._generate_protocols_html(analyzer.protocols)}

            <!-- IA ANALYSIS -->
            {ReportGenerator._generate_ai_analysis_html(ai_report)}

            <!-- RECOMENDACIONES -->
            <h1>💡 Recomendaciones de Seguridad</h1>
            {ReportGenerator._generate_recommendations_html(analyzer)}

            <div class="divider"></div>
            <p style="text-align: center; color: #64748b; margin-top: 40px; font-size: 12px;">
                Reporte generado automáticamente el {timestamp}
            </p>
        </div>
        </body>
        </html>
        """

        # Guardar HTML temporal
        html_file = f"{output_name}.html"
        with open(html_file, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"[+] HTML generado: {html_file}")

        # Convertir a PDF
        try:
            pdf_file = f"{output_name}.pdf"
            pdfkit.from_file(html_file, pdf_file)
            print(f"[+] PDF generado: {pdf_file}")
            os.remove(html_file)  # Limpiar HTML temporal
            return pdf_file
        except Exception as e:
            print(f"[!] Error generando PDF: {e}")
            print(f"[!] HTML disponible en: {html_file}")
            return None

    @staticmethod
    def _generate_risk_scores_html(scored_findings):
        if not scored_findings:
            return "<p style='color: #64748b;'>No hay hallazgos de riesgo.</p>"

        html = "<table><tr><th>Tipo</th><th>Score</th><th>Nivel</th><th>Eventos</th><th>Severidad</th></tr>"
        for finding in scored_findings:
            nivel = finding["nivel"]
            badge_class = f"badge-{nivel.lower().replace('á', 'a').replace('í', 'i')}"
            html += f"""
            <tr>
                <td><strong>{finding['tipo']}</strong></td>
                <td>{finding['score']:.1f}/100</td>
                <td><span class="badge {badge_class}">{nivel}</span></td>
                <td>{finding['count']}</td>
                <td>{finding['severidad']}</td>
            </tr>
            """
        html += "</table>"
        return html

    @staticmethod
    def _generate_credentials_html(credentials):
        if not credentials:
            return ""

        html = '<h1>🔓 Credenciales Transmitidas en Claro</h1>'
        html += '<div class="alert alert-critical"><strong>⚠️ ALERTA CRÍTICA</strong> - Se han detectado credenciales en texto plano.</div>'
        html += "<table><tr><th>Hora</th><th>Protocolo</th><th>Tipo</th><th>Origen</th><th>Valor</th></tr>"

        for cred in credentials[:50]:  # Limitar a 50
            t = cred['time'].strftime('%H:%M:%S') if isinstance(cred['time'], datetime) else str(cred['time'])
            html += f"""
            <tr>
                <td>{t}</td>
                <td><strong>{cred['protocol']}</strong></td>
                <td>{cred['type']}</td>
                <td>{cred['src']}</td>
                <td><code>{cred['value'][:60]}</code></td>
            </tr>
            """

        html += "</table>"
        return html

    @staticmethod
    def _generate_successful_logins_html(successful_logins):
        if not successful_logins:
            return ""

        html = '<h1>✅ Logins Exitosos</h1>'
        html += "<table><tr><th>Hora</th><th>Protocolo</th><th>Usuario</th><th>Origen</th><th>Destino</th></tr>"

        for login in successful_logins:
            t = login['time'].strftime('%H:%M:%S') if isinstance(login['time'], datetime) else str(login['time'])
            user = login.get('username', 'N/A')
            html += f"""
            <tr>
                <td>{t}</td>
                <td><strong>{login['protocol']}</strong></td>
                <td>{user}</td>
                <td>{login['src']}</td>
                <td>{login['dst']}</td>
            </tr>
            """

        html += "</table>"
        return html

    @staticmethod
    def _generate_brute_force_html(brute_force_attempts):
        if not brute_force_attempts:
            return ""

        html = '<h1>🚨 Ataques de Fuerza Bruta</h1>'

        for ip, attempts in brute_force_attempts.items():
            if len(attempts) < 3:
                continue

            html += f"""
            <h2>Origen: {ip} - {len(attempts)} intentos fallidos</h2>
            <table>
                <tr><th>Hora</th><th>Protocolo</th><th>Usuario</th><th>Info</th></tr>
            """

            for attempt in attempts[:20]:
                t = attempt['time'].strftime('%H:%M:%S') if isinstance(attempt['time'], datetime) else str(attempt['time'])
                user = attempt.get('username', 'N/A')
                info = attempt.get('info', '')[:40]
                html += f"""
                <tr>
                    <td>{t}</td>
                    <td>{attempt.get('protocol', 'N/A')}</td>
                    <td>{user}</td>
                    <td>{info}</td>
                </tr>
                """

            html += "</table>"

        return html

    @staticmethod
    def _generate_protocols_html(protocols):
        if not protocols:
            return "<p>Sin protocolos detectados.</p>"

        total = sum(protocols.values())
        html = "<table><tr><th>Protocolo</th><th>Paquetes</th><th>Porcentaje</th></tr>"

        for proto, count in protocols.most_common(15):
            pct = (count / total * 100) if total > 0 else 0
            html += f"<tr><td>{proto}</td><td>{count:,}</td><td>{pct:.1f}%</td></tr>"

        html += "</table>"
        return html

    @staticmethod
    def _generate_ai_analysis_html(ai_report):
        if not ai_report:
            return ""

        html = '<div class="page-break"></div><h1>🤖 Análisis de IA</h1>'
        html += f"<div style='background: #dbeafe; padding: 20px; border-radius: 6px; border-left: 4px solid #3b82f6;'>"
        html += ai_report.replace('\n', '<br>')
        html += "</div>"
        return html

    @staticmethod
    def _generate_recommendations_html(analyzer):
        html = ""

        if analyzer.credentials:
            html += """
            <div class="alert alert-critical">
                <strong>🔴 CRÍTICO - Credenciales en texto plano detectadas:</strong>
                <p>Se han encontrado credenciales transmitidas sin cifrar. Se recomienda:</p>
                <ul style="margin-left: 20px;">
                    <li>Migrar a protocolos seguros (SFTP, HTTPS, SSH)</li>
                    <li>Implementar cifrado TLS/SSL</li>
                    <li>Auditar todos los sistemas comprometidos</li>
                </ul>
            </div>
            """

        if analyzer.brute_force_attempts:
            html += """
            <div class="alert alert-warning">
                <strong>🟠 ATENCIÓN - Ataques de fuerza bruta detectados:</strong>
                <p>Se recomienda:</p>
                <ul style="margin-left: 20px;">
                    <li>Implementar rate limiting</li>
                    <li>Usar fail2ban o similar</li>
                    <li>Bloquear IPs atacantes en firewall</li>
                </ul>
            </div>
            """

        insecure_protocols = {'FTP', 'HTTP', 'TELNET', 'SMB'} & set(analyzer.protocols.keys())
        if insecure_protocols:
            html += f"""
            <div class="alert alert-info">
                <strong>🟢 MEJORAS GENERALES - Protocolos inseguros en uso:</strong>
                <p>Se detectaron: {', '.join(insecure_protocols)}</p>
                <p>Se recomienda usar alternativas seguras.</p>
            </div>
            """

        return html

    @staticmethod
    def create_report(analyzer, scored_findings, ai_report, output_json):
        """Genera reporte en JSON y PDF"""
        ReportGenerator.create_json_report(analyzer, scored_findings, ai_report, output_json)
        
        # Generar PDF
        output_pdf_base = output_json.replace('.json', '')
        ReportGenerator.create_pdf_report(analyzer, scored_findings, ai_report, output_pdf_base)


# ============================================================================
# FUNCIÓN PRINCIPAL CON FASES
# ============================================================================

def analyze_pro(pcap_file, num_threads=4, api_key=None, engine="gemini", explain=False, ai_vulns=False, mitigate=False):
    """Análisis profesional completo con todas las fases"""
    print("=" * 80)
    print("🔥 ANALIZADOR PRO CON IA - ESTRUCTURA MODULAR")
    print("=" * 80 + "\n")
    
    phase_times = {}
    
    # ── FASE 1: Extracción ─────────────────────────────────────────────────────
    print("[*] FASE 1: Extrayendo y analizando paquetes...")
    t0 = time.time()
    
    analyzer = ProTrafficAnalyzer()
    queue = Queue(maxsize=500)

    def worker():
        while True:
            pkt = queue.get()
            if pkt is None:
                queue.task_done()
                break
            analyzer.analyze_packet(pkt)
            queue.task_done()

    threads = []
    for _ in range(num_threads):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)

    print("  📂 Leyendo PCAP...", end=' ', flush=True)
    capture = pyshark.FileCapture(pcap_file, keep_packets=False)

    count = 0
    for packet in capture:
        queue.put(packet)
        count += 1
    capture.close()
    print(f"✅ {count:,} paquetes")

    print("  ⚙️  Procesando en paralelo...", end=' ', flush=True)
    queue.join()
    print("✅")

    for _ in range(num_threads):
        queue.put(None)
    for t in threads:
        t.join()

    phase_times["extraction"] = round(time.time() - t0, 2)
    print(f"[+] FASE 1 completada en {phase_times['extraction']}s\n")

    # ── FASE 2: Reporte local ──────────────────────────────────────────────────
    print("[*] FASE 2: Generando reporte local...")
    t0 = time.time()
    report_local = analyzer.generate_report()
    recommendations = analyzer.generate_recommendations()
    phase_times["local_report"] = round(time.time() - t0, 2)
    print(f"[+] FASE 2 completada en {phase_times['local_report']}s\n")

    # ── FASE 2b: Risk Scoring ──────────────────────────────────────────────────
    print("[*] FASE 2b: Calculando Risk Scores...")
    t0 = time.time()
    
    # Preparar hallazgos para scoring
    findings = []
    if analyzer.credentials:
        findings.extend([{
            "tipo": "CREDENTIALS_CLEARTEXT",
            "count": len(analyzer.credentials),
            "severity": "CRITICAL",
        }])
    if analyzer.brute_force_attempts:
        findings.extend([{
            "tipo": "BRUTE_FORCE",
            "count": sum(len(v) for v in analyzer.brute_force_attempts.values()),
            "severity": "HIGH",
        }])
    if analyzer.successful_logins:
        findings.extend([{
            "tipo": "SUCCESSFUL_COMPROMISE",
            "count": len(analyzer.successful_logins),
            "severity": "CRITICAL",
        }])

    scorer = RiskScorer()
    scored_findings = scorer.score(findings)
    phase_times["risk_scoring"] = round(time.time() - t0, 2)
    print(f"[+] FASE 2b completada en {phase_times['risk_scoring']}s\n")

    # ── FASE 3: Análisis IA ────────────────────────────────────────────────────
    ai_report = ""
    if api_key and (explain or ai_vulns or mitigate):
        print("[*] FASE 3: Análisis IA...")
        t0 = time.time()
        try:
            ai_analyzer = AIAnalyzer(api_key, engine)
            ai_report = ai_analyzer.analyze(analyzer, scored_findings, {
                "explain": explain,
                "ai_vulns": ai_vulns,
                "mitigate": mitigate,
            })
            phase_times["ai_analysis"] = round(time.time() - t0, 2)
            print(f"[+] FASE 3 completada en {phase_times['ai_analysis']}s\n")
        except Exception as e:
            print(f"[!] Error en IA: {e}\n")
    else:
        phase_times["ai_analysis"] = 0

    # ── FASE 4: Generar reportes ───────────────────────────────────────────────
    print("[*] FASE 4: Generando reportes finales...")
    t0 = time.time()
    
    output_json = f"pcap_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    ReportGenerator.create_report(analyzer, scored_findings, ai_report, output_json)
    
    phase_times["report_generation"] = round(time.time() - t0, 2)
    print(f"[+] FASE 4 completada en {phase_times['report_generation']}s\n")

    # ── Mostrar resultados ─────────────────────────────────────────────────────
    print("\n" + report_local)
    print("\n" + recommendations)

    if scored_findings:
        print("\n" + "=" * 80)
        print("📊 RISK SCORES")
        print("=" * 80)
        for finding in scored_findings:
            print(f"\n{finding['tipo']:<30} | Score: {finding['score']:>5.1f} | {finding['nivel']}")
            print(f"  Eventos: {finding['count']:<5} | Severidad: {finding['severidad']:<8} | CWE: {finding['cwe']}")
            if finding['cvss_nvd'] > 0:
                print(f"  CVSS promedio (NIST NVD): {finding['cvss_nvd']}")

    if ai_report:
        print("\n" + "=" * 80)
        print("🤖 ANÁLISIS IA")
        print("=" * 80)
        print(ai_report)

    print("\n" + "=" * 80)
    print(f"⏱️  TIEMPOS POR FASE (segundos):")
    for phase, elapsed in phase_times.items():
        print(f"  {phase:<20} {elapsed:>6.2f}s")
    print("=" * 80 + "\n")

    return analyzer
# EJECUCIÓN CLI
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="PCAP Analyzer Pro",
        description="Analizador de tráfico PCAP con IA — Extracción + Motor de Reglas + Risk Score + IA",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("pcap_file", help="Ruta al archivo PCAP a analizar")

    analysis_group = parser.add_argument_group("Opciones de Análisis Estático")
    analysis_group.add_argument("--threads", type=int, default=4,
                                help="Número de threads para procesamiento paralelo (default: 4)")

    ai_group = parser.add_argument_group("Opciones de Análisis IA")
    ai_group.add_argument("--explain", action="store_true",
                          help="Explicar qué está pasando en el tráfico")
    ai_group.add_argument("--ai-vulns", action="store_true",
                          help="Detectar vulnerabilidades en el tráfico (IA)")
    ai_group.add_argument("--mitigate", action="store_true",
                          help="Proporcionar mitigaciones y defensas")

    ai_cfg = parser.add_argument_group("Configuración del Motor de IA")
    ai_cfg.add_argument("--ai-engine", choices=["gemini", "groq"], default="gemini",
                        help="Motor de IA (default: gemini)")
    ai_cfg.add_argument("--api-key", type=str, default=None,
                        help="API Key (si no se indica, usa la del código)")

    args = parser.parse_args()

    GEMINI_API_KEY = ""
    GROQ_API_KEY = ""

    api_key = args.api_key
    if not api_key:
        api_key = GEMINI_API_KEY if args.ai_engine == "gemini" else GROQ_API_KEY

    needs_ai = args.explain or args.ai_vulns or args.mitigate

    analyze_pro(
        args.pcap_file,
        num_threads=args.threads,
        api_key=api_key if needs_ai else None,
        engine=args.ai_engine,
        explain=args.explain,
        ai_vulns=args.ai_vulns,
        mitigate=args.mitigate,
    )