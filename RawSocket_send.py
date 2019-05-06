# encoding:utf-8
import time
import random
import socket
from impacket import ImpactDecoder, ImpactPacket

def main():
    src_ip = "192.168.118.128"
    dst_ip = "192.168.118.128"
    src_port = 2018
    dst_port = 2017

    message = "hello!"
    #ip_id_hide_send(message, src_ip, dst_ip, src_port, dst_port)
    #tcp_seqnumber_hide_send(message, src_ip, dst_ip, src_port, dst_port)
    tcp_acknumber_hide_send(message, src_ip, dst_ip, src_port, dst_port)
    
    #s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    #s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    #pack = ip_tcp_pack(src_ip, dst_ip, src_port, dst_port, ip_id=2019)
    #s.sendto(pack, ("192.168.118.1", dst_port))

    return

def display(message="", src_ip="127.0.0.1", dst_ip="127.0.0.1", src_port=2333, dst_port=80):
    print("源IP地址： " + src_ip + "   源端口：" + str(src_port))
    print("目的IP地址： " + dst_ip + "   目的端口：" + str(dst_port))
    print("待发送消息：" + message)
    return 

def ip_id_hide_send(message="", src_ip="127.0.0.1", dst_ip="127.0.0.1", src_port=2333, dst_port=80):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except:
        print("创建socket失败")
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except:
        print("设置socket失败")

    print("IP标识隐蔽通道发送中:")
    display(message, src_ip, dst_ip, src_port, dst_port)

    for i in message:
        pack = ip_tcp_pack(src_ip, dst_ip, src_port, dst_port, ip_id=ord(i) + random.randint(0, 256) * 256)
        try:
            s.sendto(pack, (dst_ip, dst_port))
            print("成功发送:" + i)
            time.sleep(1)
        except:
            print("失败发送:" + i)
            return False
    return True

def tcp_seqnumber_hide_send(message="", src_ip="127.0.0.1", dst_ip="127.0.0.1", src_port=2333, dst_port=80):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except:
        print("创建socket失败")
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except:
        print("设置socket失败")

    print("TCP序号隐蔽通道发送中:")
    display(message, src_ip, dst_ip, src_port, dst_port)

    for i in message:
        pack = ip_tcp_pack(src_ip, dst_ip, src_port, dst_port, seq_num=ord(i) + random.randint(0, 1 << 24) * 256, syn=1)
        try:
            s.sendto(pack, (dst_ip, dst_port))
            print("成功发送:" + i)
            time.sleep(1)
        except:
            print("发送'" + i + "'失败")
            return False
    return True

def tcp_acknumber_hide_send(message="", src_ip="127.0.0.1", dst_ip="127.0.0.1", src_port=2333, dst_port=80, spoof_ip="14.215.177.39",spoof_port = 80):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except:
        print("创建socket失败")
    try:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except:
        print("设置socket失败")

    print("TCP确认号隐蔽通道发送中:")
    display(message, src_ip, dst_ip, src_port, dst_port)
    print("中间节点IP地址： " + spoof_ip + "   中间节点端口：" + str(spoof_port))

    for i in message:
        pack = ip_tcp_pack(dst_ip, spoof_ip, dst_port, spoof_port, seq_num=ord(i) - 1 + random.randint(0, 1 << 24) * 256, syn=1)
        try:
            s.sendto(pack, (spoof_ip, spoof_port))
            print("成功发送:" + i)
            time.sleep(1)
        except:
            print("发送'" + i + "'失败")
            return False
    return True

def ip_tcp_pack(src_ip="127.0.0.1", dst_ip="127.0.0.1", src_port=2333, dst_port=80, ip_id=0, seq_num=0,
                ack_num=0, syn=0, ack=0, windows=64):
    ip = ImpactPacket.IP()
    ip.set_ip_src(src_ip)
    ip.set_ip_dst(dst_ip)
    if ip_id != 0:
        ip.set_ip_id(ip_id)
    ip.set_ip_p(6)
    # ip.set_ip_len(40)

    tcp = ImpactPacket.TCP()
    tcp.set_th_sport(src_port)
    tcp.set_th_dport(dst_port)
    if seq_num != 0:
        tcp.set_th_seq(seq_num)
    if ack_num != 0:
        tcp.set_th_ack(ack_num)
    if syn:
        tcp.set_SYN()
    if ack:
        tcp.set_ACK()
    tcp.set_th_win(windows)
    ip.contains(tcp)
    tcp.calculate_checksum()
    return ip.get_packet()
    # Open a raw socket. Special permissions are usually required.


if __name__ == '__main__':
    main()
