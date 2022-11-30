import sys
import socket
import time
import struct
import select


# по rfc1071
def calc_checksum(header):
    res = 0
    of = 0
    for i in range(0, len(header), 2):
        word = header[i] + (header[i+1] << 8)
        res = res + word
        of = res >> 16
        while (of > 0):
            res = res & 0xFFFF
            res = res + of
            of = res >> 16
    of = res >> 16
    while (of > 0):
        res = res & 0xFFFF
        res = res + of
        of = res >> 16
    res = ~res
    res = res & 0xFFFF
    return res


def ping(target, icmp_socket, ttl):
    header = struct.pack("bbHHh", 8, 0, 0, 0, 0)   # bbHHh - type:sch(8) code:sch(8) checksum:uch(16) id:ush(16) seq:ssh(16), 8 - код эхо icmp
    checksum = calc_checksum(header)
    header = struct.pack("bbHHh", 8, 0, checksum, 0, 0) # нужный header

    icmp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, int(51-ttl)) # устанавливаем флаги, у нас ip, ttl
    icmp_socket.sendto(header, (target, 1)) # посылаем в target
    time_start = time.time() # для подсчёта времени ожидания
    socket_response = select.select([icmp_socket], [], [], 1) # 1,2 не нужны, timeout = 1s

    if socket_response[0] == []:
        print('* * *\t\t\t\t\t\t\t\t\ttime: {0}ms\tttl: {1}'.format(int((time.time() - time_start) * 1000), ttl))
        return False

    _, (ip, _) = icmp_socket.recvfrom(128) # длина буфера 128 бит

    name = ""
    try: # ищем hostname
        host = socket.gethostbyaddr(ip)
        if len(host) > 0:
            name = host[0]
    except:
        name = 'unknown'

    print('ip: {0}\thostname: {1}\ttime:{2}ms\tttl: {3}'.format(str(ip+(15-len(ip))*' '), str(name + (30-len(name))*' '), int((time.time() - time_start) * 1000), ttl))

    if (ip == target):
        return True
    return False


def main():
    if (len(sys.argv) != 2):
        print("Incorrect input")
        print("Try using the following pattern")
        print("\033[33m {}".format("python3 tracert.py hostname"))
        sys.exit()
    else:
        target_host = sys.argv[1]
        target = socket.gethostbyname(target_host)
        ttl = 50
        icmp_protocol = socket.getprotobyname("icmp")
        while(ttl > 0):          
            icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp_protocol)
            if (ping(target, icmp_socket, ttl)):
                icmp_socket.close()
                break
            ttl -= 1
            icmp_socket.close()
        sys.exit()


if __name__ == "__main__":
    main()
    
