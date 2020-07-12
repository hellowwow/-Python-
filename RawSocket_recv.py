# encoding:utf-8
import socket
from struct import *
修改3

def main():
    src_ip = "192.168.118.128"
    dst_ip = "192.168.118.128"
    src_port = 2018
    dst_port = 2017

    #ip_id_hide_recv(src_ip, dst_ip, src_port, dst_port)
    #tcp_seqnumber_hide_recv(src_ip, dst_ip, src_port, dst_port)
    tcp_acknumber_hide_recv(src_ip, dst_ip, src_port, dst_port)

    return

def display(src_ip="127.0.0.1", dst_ip="127.0.0.1", src_port=2333, dst_port=80):
    print("源IP地址： " + src_ip + "   源端口：" + str(src_port))
    print("目的IP地址： " + dst_ip + "   目的端口：" + str(dst_port))
    return 


def ip_id_hide_recv(src_ip="127.0.0.1", dst_ip="127.0.0.1", src_port=0, dst_port=0):
    src_addr = (src_ip, src_port)
    dst_addr = (dst_ip, dst_port)

    print("IP标识隐蔽通道监听中：")
    display(src_ip, dst_ip, src_port, dst_port)

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except:
        print("创建socket失败")
        return 0
    while True:
        try:
            packet, recv_addr = s.recvfrom(6000, 0)  # (data, addr)
        except:
            print("接收数据包失败")
            return 0
        fields = packet_trans(packet)
        recv_src_addr = (fields["Source Address"], fields["Source Port"])
        recv_dst_addr = (fields["Destination Address"], fields["Destination Port"])
        if src_addr == recv_src_addr and dst_addr == recv_dst_addr:
            print("成功接收：" + chr(fields["Identification"] % 256))
    return 1

def tcp_seqnumber_hide_recv(src_ip="127.0.0.1", dst_ip="127.0.0.1", src_port=0, dst_port=0):
    src_addr = (src_ip, src_port)
    dst_addr = (dst_ip, dst_port)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except:
        print("创建socket失败")

    print("TCP序号隐蔽通道监听中：")
    display(src_ip, dst_ip, src_port, dst_port)

    while True:
        try:
            packet, recv_addr = s.recvfrom(6000, 0)  # (data, addr)
        except:
            print("接收数据包失败")
        fields = packet_trans(packet)
        recv_src_addr = (fields["Source Address"], fields["Source Port"])
        recv_dst_addr = (fields["Destination Address"], fields["Destination Port"])
        if src_addr == recv_src_addr and dst_addr == recv_dst_addr:
            print("成功接收：" + chr(fields["Seq Number"] % 256))


def tcp_acknumber_hide_recv(src_ip="127.0.0.1", dst_ip="127.0.0.1", src_port=0, dst_port=0):
    src_addr = (src_ip, src_port)
    dst_addr = (dst_ip, dst_port)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except:
        print("创建socket失败")
    
    print("TCP确认号隐蔽通道监听中：")
    display(src_ip, dst_ip, src_port, dst_port)

    while True:
        try:
            packet, recv_addr = s.recvfrom(6000, 0)  # (data, addr)
        except:
            print("接收数据包失败")
        fields = packet_trans(packet)
        recv_dst_addr = (fields["Destination Address"], fields["Destination Port"])
        if dst_addr == recv_dst_addr:
            print("成功接收：" + chr(fields["Ack Number"] % 256))


def packet_trans(packet=None):
    if packet == None:
        print("数据包为空")
        return

    raw_iph = packet[0:20]  # 尚未解析的IP数据报头部固定部分
    # unpack(fmt, buffer) - 根据指定的格式化字符串来拆解给定的buffer
    # B 单字节的整型
    # H 双字节的整型
    # s bytes，前加数字表示取4字节的bytes
    iph = unpack("!BBHHHBBH4s4s", raw_iph)
    fields = {}
    fields["Version"] = iph[0] >> 4  # 版本字段与IP数据报头部共享一个字节，通过右移操作取得单独的版本字段
    fields["IP Header Length"] = (iph[0] & 0xF) * 4  # 首部长度字段的1代表4个字节
    fields["Type of Service"] = iph[1]  # 区分服务，一般情况下并不使用
    fields["Total Length"] = iph[2]  # IP首部+数据的总长度，即len(packet)
    fields["Identification"] = iph[3]  # 标识
    flags = iph[4] >> 13  # 标识位与片偏移共享2个字节，且最高位并且未使用
    fields["MF"] = 1 if flags & 1 else 0  # 测试最低位
    fields["DF"] = 1 if flags & 1 else 0  # 测试中间位
    fields["Fragment Offset"] = iph[4] & 0x1FFF  # 位与操作取得片偏移
    fields["Time to Live"] = iph[5]  # 生存时间，单位是跳数
    fields["Protocol"] = iph[6]  # 数据报携带的数据使用的协议，TCP为6
    fields["Header Checksum"] = iph[7]  # 首部校验和

    fields["Source Address"] = socket.inet_ntoa(iph[8])
    fields["Destination Address"] = socket.inet_ntoa(iph[9])

    raw_tcph = packet[20:40]  #  提取TCP首部部分
    tcph = unpack("!HHLLHHHH", raw_tcph)
    fields["Source Port"] = tcph[0]  # 源端口
    fields["Destination Port"] = tcph[1]  # 目的端口
    fields["Seq Number"] = tcph[2]  # 序号
    fields["Ack Number"] = tcph[3]  # 确认号
    fields["URG"] = (tcph[4] >> 5) & 1
    fields["ACK"] = (tcph[4] >> 4) & 1
    fields["PSH"] = (tcph[4] >> 3) & 1
    fields["RST"] = (tcph[4] >> 2) & 1
    fields["SYN"] = (tcph[4] >> 1) & 1
    fields["FIN"] = (tcph[4]) & 1
    fields["Windows"] = tcph[5]
    fields["Checksum"] = tcph[6]


    #for k, v in fields.items():  # 遍历打印，由于是dict，因此打印是无序的
    #    print(k, ':', v)
    return fields


if __name__ == '__main__':
    main()
