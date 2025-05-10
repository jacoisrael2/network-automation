import socket
import ipaddress
import csv
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import platform
import subprocess

def scan_port(ip, port):
    """Função para verificar se uma porta está aberta"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)  # Timeout reduzido para maior velocidade
    result = sock.connect_ex((str(ip), port))
    sock.close()
    return port if result == 0 else None

def check_host(ip):
    """Função para verificar se um host está ativo usando ping"""
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', str(ip)]
    try:
        output = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return output.returncode == 0
    except:
        return False

def scan_host(ip):
    """Função para escanear portas de um host"""
    print(f"\nEscaneando IP: {ip}")
    open_ports = []
    # Escaneando portas comuns (1-1024)
    with ThreadPoolExecutor(max_workers=100) as executor:  # Aumentado número de workers
        ports = range(1, 1025)
        results = executor.map(lambda p: scan_port(ip, p), ports)
        open_ports = [p for p in results if p is not None]
    return str(ip), open_ports

def main():
    try:
        # Solicita a rede ao usuário
        network = input("Digite a rede a ser escaneada (ex: 192.168.1.0/24): ")
        
        # Converte a entrada em um objeto de rede
        net = ipaddress.ip_network(network)
        
        # Lista para armazenar resultados
        results = []
        active_hosts = []
        
        print(f"\nIniciando descoberta de hosts ativos na rede {network} usando PING")
        
        # Verifica hosts ativos usando PING
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(check_host, ip): ip for ip in net.hosts()}
            for future in futures:
                ip = futures[future]
                if future.result():
                    active_hosts.append(ip)
                    print(f"Host ativo encontrado: {ip}")
        
        print(f"\nHosts ativos encontrados: {len(active_hosts)}")
        print("Iniciando varredura de portas nos hosts ativos...")
        
        # Escaneia portas nos hosts ativos
        with ThreadPoolExecutor(max_workers=20) as executor:
            scan_results = list(executor.map(scan_host, active_hosts))
            results.extend([r for r in scan_results if r[1]])
        
        # Gera nome do arquivo com timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_result_{timestamp}.csv"
        
        # Salva resultados em CSV
        with open(filename, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['IP', 'Portas Abertas'])
            for ip, ports in results:
                writer.writerow([ip, ', '.join(map(str, ports))])
        
        print(f"\nVarredura concluída! Resultados salvos em {filename}")
        print(f"\nResumo da varredura:")
        print(f"Total de hosts ativos: {len(active_hosts)}")
        print(f"Total de hosts com portas abertas: {len(results)}")
        
        # Mostra resultados no terminal
        for ip, ports in results:
            print(f"\nIP: {ip}")
            print(f"Portas abertas: {', '.join(map(str, ports))}")
            
    except Exception as e:
        print(f"Erro: {e}")

if __name__ == "__main__":
    main()
