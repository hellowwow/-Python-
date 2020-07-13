# encoding:utf-8
import tkinter.font as tkFont
import tkinter
import RawSocket_send
import RawSocket_recv
import socket

win = tkinter.Tk()
win.title("WELCOME")
win.geometry("900x550")

#添加修改2
123

ft = tkFont.Font(family='Fiddly', size=18, weight=tkFont.BOLD)

frm1 = tkinter.Frame(win)
frm1.place(x=119, y=80)
radio_var = tkinter.IntVar()


def Click_ipv4():
    for widget in frm1.winfo_children():
        widget.destroy()
    radio1 = tkinter.Radiobutton(frm1, text="Identification", value=1, variable=radio_var, font=ft, fg='blue')
    radio1.pack(anchor=tkinter.W)
    radio2 = tkinter.Radiobutton(frm1, text="Time To Live", value=2, variable=radio_var, font=ft, fg='blue')
    radio2.pack(anchor=tkinter.W)
    radio2 = tkinter.Radiobutton(frm1, text="Source Address", value=12, variable=radio_var, font=ft, fg='blue')
    radio2.pack(anchor=tkinter.W)
    radio2 = tkinter.Radiobutton(frm1, text="Fragment Offset", value=13, variable=radio_var, font=ft, fg='blue')
    radio2.pack(anchor=tkinter.W)


def Click_ipv6():
    for widget in frm1.winfo_children():
        widget.destroy()
    # r = tkinter.IntVar()
    radio1 = tkinter.Radiobutton(frm1, text="2", value=3, variable=radio_var, font=ft, fg='blue')
    radio1.pack(anchor=tkinter.W)
    radio2 = tkinter.Radiobutton(frm1, text="3", value=4, variable=radio_var, font=ft, fg='blue')
    radio2.pack(anchor=tkinter.W)
    radio3 = tkinter.Radiobutton(frm1, text="4", value=5, variable=radio_var, font=ft, fg='blue')
    radio3.pack(anchor=tkinter.W)


def Click_tcp():
    for widget in frm1.winfo_children():
        widget.destroy()
    # r = tkinter.IntVar()
    radio1 = tkinter.Radiobutton(frm1, text="SeqNumber", value=6, variable=radio_var, font=ft, fg='blue')
    radio1.pack(anchor=tkinter.W)
    radio2 = tkinter.Radiobutton(frm1, text="AckNumber", value=7, variable=radio_var, font=ft, fg='blue')
    radio2.pack(anchor=tkinter.W)


def Click_udp():
    for widget in frm1.winfo_children():
        widget.destroy()
    # r = tkinter.IntVar()
    radio1 = tkinter.Radiobutton(frm1, text="55", value=8, variable=radio_var, font=ft, fg='blue')
    radio1.pack(anchor=tkinter.W)
    radio2 = tkinter.Radiobutton(frm1, text="35", value=9, variable=radio_var, font=ft, fg='blue')
    radio2.pack(anchor=tkinter.W)


def Click_icmp():
    for widget in frm1.winfo_children():
        widget.destroy()
    # r = tkinter.IntVar()
    radio1 = tkinter.Radiobutton(frm1, text="4", value=10, variable=radio_var, font=ft, fg='blue')
    radio1.pack(anchor=tkinter.W)
    radio2 = tkinter.Radiobutton(frm1, text="5", value=11, variable=radio_var, font=ft, fg='blue')
    radio2.pack(anchor=tkinter.W)


def Click_Send():
    message = tx_send.get('1.0', 'end')
    if radio_var.get() == 1:
        if RawSocket_send.ip_id_hide_send(message.encode('gbk'), srcip.get(), dstip.get(), int(srcport.get()),
                                          int(dstport.get())):
            print("发送成功")
        else:
            print("发送失败")
    elif radio_var.get() == 6:
        if RawSocket_send.tcp_seqnumber_hide_send(message.encode('gbk'), srcip.get(), dstip.get(), int(srcport.get()),
                                                  int(dstport.get())):
            print("发送成功")
        else:
            print("发送失败")
    elif radio_var.get() == 7:
        if RawSocket_send.tcp_acknumber_hide_send(message.encode('gbk'), srcip.get(), dstip.get(), int(srcport.get()),
                                                  int(dstport.get())):
            print("发送成功")
        else:
            print("发送失败")


def Click_Recv():
    # if radio_var.get() == 1:
    # ip_id_hide_recv(srcip.get(), dstip.get(), int(srcport.get()), int(dstport.get()))

    src_ip = srcip.get()
    dst_ip = dstip.get()
    src_port = int(srcport.get())
    dst_port = int(dstport.get())

    src_addr = (src_ip, src_port)
    dst_addr = (dst_ip, dst_port)
    # print("IP标识隐蔽通道监听中：")
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
        fields = RawSocket_recv.packet_trans(packet)
        recv_src_addr = (fields["Source Address"], fields["Source Port"])
        recv_dst_addr = (fields["Destination Address"], fields["Destination Port"])
        if src_addr == recv_src_addr and dst_addr == recv_dst_addr:
            # message = message + chr(fields["Identification"] % 256)
            recv_c = ''
            if radio_var.get() == 1:
                recv_c = chr(fields["Identification"] % 256)
            elif radio_var.get() == 6:
                recv_c = chr(fields["Seq Number"] % 256)
            elif radio_var.get() == 7:
                recv_c = chr(fields["Ack Number"] % 256)

            tx_recv.insert(tkinter.END, recv_c)

            tx_recv.update()
            print("成功接收：" + recv_c)
    return 1


def display(src_ip="127.0.0.1", dst_ip="127.0.0.1", src_port=2333, dst_port=80):
    print("源IP地址： " + src_ip + "   源端口：" + str(src_port))
    print("目的IP地址： " + dst_ip + "   目的端口：" + str(dst_port))


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
        fields = RawSocket_recv.packet_trans(packet)
        recv_src_addr = (fields["Source Address"], fields["Source Port"])
        recv_dst_addr = (fields["Destination Address"], fields["Destination Port"])
        if src_addr == recv_src_addr and dst_addr == recv_dst_addr:
            # message = message + chr(fields["Identification"] % 256)
            tx_recv.insert(tkinter.END, chr(fields["Identification"] % 256))
            tx_recv.update()
            print("成功接收：" + chr(fields["Identification"] % 256))
    return 1


but_ipv4 = tkinter.Button(win, text='IPv4', font=ft, relief='raised', width=5, height=1, fg='blue', command=Click_ipv4)
but_ipv4.place(x=0, y=0)
but_ipv6 = tkinter.Button(win, text='IPv6', font=ft, relief='raised', width=5, height=1, fg='blue', command=Click_ipv6)
but_ipv6.place(x=110, y=0)
but_tcp = tkinter.Button(win, text='TCP', font=ft, relief='raised', width=5, height=1, fg='blue', command=Click_tcp)
but_tcp.place(x=220, y=0)
but_udp = tkinter.Button(win, text='UDP', font=ft, relief='raised', width=5, height=1, fg='blue', command=Click_udp)
but_udp.place(x=330, y=0)
but_icmp = tkinter.Button(win, text='ICMP', font=ft, relief='raised', width=5, height=1, fg='blue', command=Click_icmp)
but_icmp.place(x=440, y=0)

# tx1 = tkinter.Text(win, width=20, height=60)
# Label(tx1, text="Message:", font=('times', 21, 'italic'), fg='blue', width=25, height=1, anchor=tkinter.W).pack()
# tx1.place(x=550, y=0)


tkinter.Label(win, text="SrcIP:", font=ft, fg='blue').place(x=20, y=340)
tkinter.Label(win, text="DstIP:", font=ft, fg='blue').place(x=20, y=380)
tkinter.Label(win, text="SrcPort:", font=ft, fg='blue').place(x=285, y=341)
tkinter.Label(win, text="DstPort:", font=ft, fg='blue').place(x=285, y=380)

srcip = tkinter.StringVar()
dstip = tkinter.StringVar()
srcport = tkinter.StringVar()
dstport = tkinter.StringVar()
entry1 = tkinter.Entry(win, textvariable=srcip)
entry2 = tkinter.Entry(win, textvariable=dstip)
entry3 = tkinter.Entry(win, textvariable=srcport)
entry4 = tkinter.Entry(win, textvariable=dstport)
entry1.place(x=110, y=346)
entry2.place(x=110, y=386)
entry3.place(x=400, y=346)
entry4.place(x=400, y=386)

Click_ipv4()

but1 = tkinter.Button(win, text='Send_Message:', font=ft, relief='flat', width=30, height=1, fg='blue',
                      state="disabled", anchor=tkinter.W)
but1.place(x=570, y=0)
tx_send = tkinter.Text(win, width=23, height=10, font=('times', 17, 'italic'))
tx_send.place(x=570, y=60)
but_send = tkinter.Button(win, font=ft, fg='blue', text="Send", width=6, height=1, command=Click_Send)
but_send.place(x=630, y=360)

but2 = tkinter.Button(win, text='Recv_Message:', font=ft, relief='flat', width=30, height=1, fg='blue',
                      state="disabled", anchor=tkinter.W)
but2.place(x=850, y=0)
tx_recv = tkinter.Text(win, width=23, height=10, font=('times', 17, 'italic'))
tx_recv.place(x=850, y=60)
but_recv = tkinter.Button(win, font=ft, fg='blue', text="Recv", width=6, height=1, command=Click_Recv)
but_recv.place(x=910, y=360)

win.mainloop()
