import os
import requests
import socket
import concurrent.futures

os.system('clear')

def banner(text):
    purple_text = "\033[94m" + text + "\033[0m"
    print(purple_text)

text = """\
W       W  AAAAA  TTTTT  CCCC  H   H  FFFFF  U   U  L
W   W   W  A   A   T   C     C  H   H  F      U   U  L
W   W   W  AAAAA   T   C       HHHHH  FFFF   U   U  L
W W   W W  A   A   T   C     C  H   H  F      U   U  L
 W     W   A   A   T    CCCC  H   H  F       UUU   LLLLL
"""

banner(text)
print("\033[94m___________________Create by Uno 1.0_____________________")

ip = input("\033[94mInsira o IP que deseja escanear: ")

def is_valid_ip(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return "IPv4"
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return "IPv6"
        except socket.error:
            return None

def is_private_ip(ip):
    try:
        ip_bytes = socket.inet_pton(socket.AF_INET, ip)
        if ip_bytes.startswith(b'\x0A') or ip_bytes.startswith(b'\x7F') or (b'\xC0A8' <= ip_bytes < b'\xC0B0') or (b'\xA9FE' <= ip_bytes < b'\xA9FF'):
            return True
    except socket.error:
        try:
            ip_bytes = socket.inet_pton(socket.AF_INET6, ip)
            if ip_bytes.startswith(b'\xFE80') or ip_bytes.startswith(b'\xFEC0') or (b'\xFEC0' <= ip_bytes < b'\FEC8'):
                return True
        except socket.error:
            return False
    return False

def convert_to_ipv6(ip):
    try:
        ipv4_bytes = socket.inet_pton(socket.AF_INET, ip)
        ipv6_bytes = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff' + ipv4_bytes
        return socket.inet_ntop(socket.AF_INET6, ipv6_bytes)
    except socket.error:
        return ip

def convert_to_ipv4(ip):
    try:
        ipv6_bytes = socket.inet_pton(socket.AF_INET6, ip)
        ipv4_bytes = ipv6_bytes[-4:]
        return socket.inet_ntop(socket.AF_INET, ipv4_bytes)
    except socket.error:
        return ip

def is_public_ip(ip):
    try:
        url = f'https://ipinfo.io/{ip}/json'
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            return True
    except Exception as e:
        return False

def get_ip_info(ip):
    try:
        url = f'https://ipinfo.io/{ip}/json'
        response = requests.get(url)

        if response.status_code == 200:
            data = response.json()
            return data
    except Exception as e:
        print(f"\033[94mErro ao obter informações do IP: {e}\033[0m")
    return None

def check_web_service_status(ip, port):
    url = f'http://{ip}:{port}'
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return "Online"
        else:
            return "Offline"
    except requests.exceptions.RequestException:
        return "Não foi possível conectar"

def get_dns_info(ip):
    try:
        host_info = socket.gethostbyaddr(ip)
        return host_info
    except socket.herror:
        return None

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                return port
    except Exception as e:
        pass
    return None

def scan_ports(ip, ports):
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = list(executor.map(lambda port: scan_port(ip, port), ports))
        open_ports = [port for port in results if port is not None]
    return open_ports

def check_blacklists(ip):
    blacklists = [
        ("http://www.spamhaus.org/query/bl?ip=", "Spamhaus"),
        ("http://www.openrbl.org/query?ip=", "OpenRBL"),
        ("http://www.projecthoneypot.org/ip_", "Project Honey Pot"),
        ("http://www.dnsbl.info/dnsbl-database-check.php?ip=", "DNSBL Info (Database Check)"),
        ("http://www.dnsbl.info/dnsbl-lookup.php?ip=", "DNSBL Info (Lookup)"),
        ("http://www.abuseat.org/lookup.cgi?ip=", "Abuseat"),
    ]

    print(f"\033[94mO IP {ip} está sendo verificado em listas negras:")
    for url, blacklist in blacklists:
        try:
            response = requests.get(url + ip)
            if "LISTED" in response.text:
                print(f"\033[94mO IP {ip} está listado na blacklist: {blacklist}\033[0m")
            else:
                print(f"\033[94mO IP {ip} não está listado na blacklist: {blacklist}\033[0m")
        except Exception as e:
            print(f"\033[94mNão foi possível verificar a blacklist {blacklist}: {e}\033[0m")

def format_ipv4_and_ipv6(ip, version):
    if version == "IPv4":
        ipv6_equivalent = convert_to_ipv6(ip)
        return f"IPv4: {ip}, IPv6 equivalente: {ipv6_equivalent}"
    elif version == "IPv6":
        ipv4_equivalent = convert_to_ipv4(ip)
        return f"IPv6: {ip}, IPv4 equivalente: {ipv4_equivalent}"
    else:
        return f"IP inválido: {ip}"

def get_internal_ip():
    try:
        internal_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        internal_socket.settimeout(0.1)
        internal_socket.connect(("10.0.0.0", 80))
        internal_ip = internal_socket.getsockname()[0]
        internal_socket.close()
        return internal_ip
    except Exception as e:
        return None

if __name__ == "__main__":
    version = is_valid_ip(ip)
    if version:
        print(format_ipv4_and_ipv6(ip, version))
    else:
        print("\033[94mIP inválido\033[0m")

    is_public = is_public_ip(ip)

    internal_ip = get_internal_ip()
    if internal_ip:
        print(f"IP interno do seu dispositivo: {internal_ip}")
        if is_private_ip(internal_ip):
            print("Tipo de conexão: Privada")
        else:
            print("Tipo de conexão: Pública")
    else:
        print("Não foi possível determinar o IP interno do dispositivo.")

    if is_public:
        ip_info = get_ip_info(ip)
        if ip_info:
            print("\033[94mInformações do IP:\033[0m")
            print(f"\033[94mIP: {ip_info.get('ip', '')}\033[0m")
            print(f"\033[94mHostname: {ip_info.get('hostname', '')}\033[0m")
            print(f"\033[94mCidade: {ip_info.get('city', '')}\033[0m")
            print(f"\033[94mRegião: {ip_info.get('region', '')}\033[0m")
            print(f"\033[94mPaís: {ip_info.get('country', '')}\033[0m")
            print(f"\033[94mProvedor de Internet: {ip_info.get('org', '')}\033[0m")
            print(f"\033[94mLocalização Geográfica: {ip_info.get('loc', '')}\033[0m")
            print(f"\033[94mFuso Horário: {ip_info.get('timezone', '')}\033[0m")
            print(f"\033[94mCEP: {ip_info.get('postal', '')}\033[0m")
            print(f"\033[94mCoordenadas: {ip_info.get('loc', '')}\033[0m")

    dns_info = get_dns_info(ip)
    if dns_info:
        print("\033[94mInformações de DNS:\033[0m")
        print(f"\033[94mNome do Host: {dns_info[0]}\033[0m")
        print(f"\033[94mEndereço de Host: {dns_info[2]}\033[0m")

    check_blacklists(ip)

    ports = [20, 21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 465, 587, 993, 995, 3389]
    open_ports = scan_ports(ip, ports)
    if open_ports:
        print("\033[94mPortas abertas:")
        for port in open_ports:
            print(f"\033[94mPorta {port}: {check_web_service_status(ip, port)}\033[0m")
