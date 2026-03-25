import socket
import os
import struct
import time
import select
import sys

ICMP_ECHO_REQUEST = 8
ICMP_TIME_EXCEEDED = 11
ICMP_ECHO_REPLY = 0


def checksum(source_string):
    """Подсчет контрольной суммы (RFC 1071)"""
    sum = 0
    count_to = (len(source_string) // 2) * 2
    count = 0
    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        sum = sum + this_val
        sum = sum & 0xffffffff
        count = count + 2

    if count_to < len(source_string):
        sum = sum + source_string[len(source_string) - 1]
        sum = sum & 0xffffffff

    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def create_packet(id, seq):
    """Создает ICMP Echo Request пакет"""
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, id, seq)
    data = struct.pack("d", time.time())

    #контрольная сумма заголовка и данных
    my_checksum = checksum(header + data)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), id, seq)
    return header + data


def get_route(hostname, max_hops=30, timeout=2, resolve_names=False):
    try:
        dest_addr = socket.gethostbyname(hostname)
    except socket.gaierror:
        print(f"Ошибка: невозможно разрешить имя {hostname}")
        return

    print(f"Трассировка маршрута к {hostname} [{dest_addr}]")
    print(f"Максимальное число прыжков: {max_hops}\n")

    icmp_proto = socket.getprotobyname("icmp")
    packet_id = os.getpid() & 0xFFFF

    for ttl in range(1, max_hops + 1):
        print(f"{ttl:2}  ", end="", flush=True)

        curr_addr = None
        curr_name = None

        #3 пакета для каждого TTL
        for seq in range(3):
            try:

                my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp_proto)
                my_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
                my_socket.settimeout(timeout)

                packet = create_packet(packet_id, ttl * 100 + seq)
                my_socket.sendto(packet, (dest_addr, 1))

                start_time = time.time()

                # Ждем ответа через select (для более точного управления таймаутом)
                ready = select.select([my_socket], [], [], timeout)
                if ready[0] == []:
                    print("*       ", end="", flush=True)
                else:
                    recv_packet, addr = my_socket.recvfrom(1024)
                    time_received = time.time()
                    curr_addr = addr[0]

                    # Извлекаем ICMP заголовок из IP пакета (IP заголовок - первые 20 байт)
                    icmp_header = recv_packet[20:28]
                    type, code, checksum_val, p_id, p_seq = struct.unpack("bbHHh", icmp_header)

                    rtt = (time_received - start_time) * 1000
                    print(f"{rtt:4.0f} ms ", end="", flush=True)

            except socket.error as e:
                print(f"Error: {e}", end="")
            finally:
                my_socket.close()

        if curr_addr:
            if resolve_names:
                try:
                    host_info = socket.gethostbyaddr(curr_addr)
                    curr_name = host_info[0]
                    print(f" {curr_name} [{curr_addr}]")
                except socket.herror:
                    print(f" {curr_addr}")
            else:
                print(f" {curr_addr}")
        else:
            print(" Превышен интервал ожидания запроса.")

        if curr_addr == dest_addr:
            print("\nТрассировка завершена.")
            break


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Использование: python traceroute.py <target_ip_or_host> [-n]")
        print("Параметры: -n (опционально) — разрешать IP в имена узлов")
        sys.exit(1)

    target = sys.argv[1]
    resolve = "-n" in sys.argv

    try:
        get_route(target, resolve_names=resolve)
    except PermissionError:
        print("\nОшибка: Недостаточно прав. Запустите скрипт от имени администратора (sudo).")