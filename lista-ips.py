# Importando as bibliotecas necessárias
import ipaddress  # Para trabalhar com endereços IP e redes
import socket  # Para fazer consultas DNS
import concurrent.futures  # Para executar tarefas em paralelo
import platform  # Para identificar o sistema operacional
import subprocess  # Para executar comandos do sistema (ping)
from datetime import datetime  # Para registrar horários
import csv  # Para salvar resultados em arquivos CSV
import os  # Para operações com arquivos e diretórios

def check_ip_windows(ip):
    """Função que verifica se um IP está respondendo no Windows usando o comando ping"""
    try:
        # Executa o comando ping com timeout de 500ms e apenas 1 tentativa
        output = subprocess.run(['ping', '-n', '1', '-w', '500', str(ip)], capture_output=True)
        # Retorna True se o ping foi bem sucedido (returncode = 0)
        return output.returncode == 0
    except:
        return False

def check_ip_linux(ip):
    """Função que verifica se um IP está respondendo no Linux usando o comando ping"""
    try:
        # Executa o comando ping com timeout de 1s e apenas 1 tentativa
        output = subprocess.run(['ping', '-c', '1', '-W', '1', str(ip)], capture_output=True)
        # Retorna True se o ping foi bem sucedido (returncode = 0)
        return output.returncode == 0
    except:
        return False

def get_dns_info(ip):
    """Função que tenta obter o nome do host (DNS) e DNS reverso de um IP"""
    # Dicionário para armazenar as informações DNS
    dns_info = {
        'hostname': None,
        'reverse_dns': None
    }
    
    try:
        # Tenta obter o nome do host a partir do IP
        dns_info['hostname'] = socket.gethostbyaddr(str(ip))[0]
    except:
        dns_info['hostname'] = "Hostname não encontrado"
        
    try:
        # Tenta obter o IP a partir do nome do host (DNS reverso)
        dns_info['reverse_dns'] = socket.gethostbyname(dns_info['hostname'])
    except:
        dns_info['reverse_dns'] = "DNS reverso não encontrado"
        
    return dns_info

def scan_network(network):
    """Função principal que faz a varredura de todos os IPs de uma rede"""
    # Mostra mensagem inicial com horário
    print(f"\nIniciando varredura da rede {network} em {datetime.now()}\n")
    
    # Cria um objeto de rede para trabalhar com o range de IPs
    net = ipaddress.ip_network(network, strict=False)
    
    # Escolhe a função de ping adequada ao sistema operacional
    check_ip = check_ip_windows if platform.system().lower() == "windows" else check_ip_linux
    
    # Listas para armazenar resultados
    active_hosts = []  # IPs que responderam
    all_hosts = []  # Todos os IPs verificados
    
    # Cria um pool de threads para verificar múltiplos IPs simultaneamente
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        # Mapeia cada IP para uma tarefa de verificação
        future_to_ip = {executor.submit(check_ip, ip): ip for ip in net.hosts()}
        
        # Processa os resultados conforme ficam prontos
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            ip_str = str(ip)
            
            # Obtém informações DNS do IP
            dns_info = get_dns_info(ip)
            
            # Cria dicionário com informações do host
            host_info = {
                'ip': ip_str,
                'icmp_response': False,
                'hostname': dns_info['hostname'],
                'reverse_dns': dns_info['reverse_dns']
            }
            
            try:
                # Verifica se o ping teve sucesso
                host_info['icmp_response'] = future.result()
                if host_info['icmp_response']:
                    active_hosts.append(host_info)
                    print(f"IP Ativo: {ip_str} - Hostname: {host_info['hostname']} - DNS Reverso: {host_info['reverse_dns']}")
            except Exception as e:
                print(f"Erro ao verificar {ip}: {str(e)}")
                
            all_hosts.append(host_info)
    
    # Mostra resumo da varredura
    print(f"\nVarredura concluída em {datetime.now()}")
    print(f"Total de hosts ativos encontrados: {len(active_hosts)}")
    
    return all_hosts, active_hosts

def save_results_csv(hosts, network, active_only=False):
    """Função que salva os resultados em um arquivo CSV"""
    # Gera nome do arquivo com timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"scan_result_{network.replace('/', '_')}_{timestamp}_{'active' if active_only else 'all'}.csv"
    
    # Cria e escreve no arquivo CSV
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['ip', 'icmp_response', 'hostname', 'reverse_dns']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for host in hosts:
            writer.writerow(host)
            
    return filename

def main():
    """Função principal que controla o fluxo do programa"""
    while True:
        try:
            # Solicita a rede a ser verificada
            network = input("\nDigite a rede a ser verificada (ex: 192.168.1.0/24) ou 'sair' para encerrar: ")
            
            # Verifica se usuário quer sair
            if network.lower() == 'sair':
                print("Encerrando programa...")
                break
                
            # Executa a varredura
            all_hosts, active_hosts = scan_network(network)
            
            # Salva os resultados em arquivos CSV
            all_hosts_file = save_results_csv(all_hosts, network)
            active_hosts_file = save_results_csv(active_hosts, network, active_only=True)
            
            # Mostra onde os resultados foram salvos
            print(f"\nResultados completos salvos em: {all_hosts_file}")
            print(f"Apenas hosts ativos salvos em: {active_hosts_file}")
                
        except ValueError as e:
            print(f"Erro: Formato de rede inválido - {str(e)}")
        except Exception as e:
            print(f"Erro inesperado: {str(e)}")

# Ponto de entrada do programa
if __name__ == "__main__":
    main()
