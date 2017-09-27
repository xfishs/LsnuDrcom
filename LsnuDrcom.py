# coding: utf-8

from struct import pack, unpack
from fcntl import ioctl
import socket
from hashlib import md5
from select import select
import time
import sys
import keepalive


class Utils:
    @staticmethod
    def get_ip_index(sock, iface):
        SIOCGFINDEX = 0x8933
        if_name, index = unpack("16sI", ioctl(
            sock, SIOCGFINDEX, pack("16sI", iface, 0)
        ))
        return index

    @staticmethod
    def get_hw_addr(sock, iface):
        SIOCGIFHWADDR = 0x8927
        if_name, _, hw_addr = unpack("16sH6s", ioctl(
            sock, SIOCGIFHWADDR, pack("16sH6s", iface, 0, '')
        ))
        return hw_addr

    @staticmethod
    def get_ip_address(iface):
        try:            
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ip = socket.inet_ntoa(ioctl(
                s.fileno(),
                0x8915,  # SIOCGIFADDR
                pack('256s', iface[:15])
            )[20:24])
        except:
            ip = '0.0.0.0'     #第一次运行，路由中没有ip会失败，第二次后就会正常
        return ip

class DrComSupplicant:
    def __init__(self, iface, username, password):
        self.ETH_P_PAE = 0x888E
        self.ETH_P_IP = 0x0800
        self.iface = iface
        self.state = 0
        self.username = username
        self.password = password
        self.server_hw_addr = None
        self.sock = socket.socket(17, socket.SOCK_RAW, socket.htons(self.ETH_P_PAE))
        self.sock.bind((iface, 0))
        self.if_index = Utils.get_ip_index(self.sock, self.iface)
        self.hw_addr_text = ":".join([x.encode('hex') for x in Utils.get_hw_addr(self.sock, self.iface)])
        self.hw_addr = Utils.get_hw_addr(self.sock, self.iface)
        self.pae_group_addr = '\xff'*6
        self.last_start = None
        self.md5_load = None
        self.udp_process = None
        self.ip_addr = Utils.get_ip_address(self.iface)
        self._info()


    def _info(self):
        print("Python Version of DrCom in Lsnu\n---------------------------\n"
              "By xfishs\n QQ group: 348609229\n------------------------\n"
              "Ip: {}\nMac: {}".format(
            self.ip_addr, self.hw_addr_text
        ))
        print("Username: {}\nPassword: {}\nInterface: {}".format(
            self.username, self.password, self.iface
        ))


    def make_ether_header(self):
        return pack('>6s6sH', self.pae_group_addr, self.hw_addr, self.ETH_P_PAE)

    
    def make_8021x_header(self, x_type, length=0):
	if length > 0 :
	    return pack('BBBB', 1, x_type,0, length + 9)
        return pack('BBH', 1, x_type, length)


    def make_eap_pkt(self, eap_code, eap_id, eap_data):
        return pack('>BBH%ds' % len(eap_data), eap_code, eap_id, len(eap_data) + 13, eap_data)


    def send_start(self):
        X_TYPE_START = 1
        pkt = self.make_ether_header() + self.make_8021x_header(X_TYPE_START, 0)
        length = len(pkt)
        pkt += '\x00' * (96 - length)
        print 'start pkt = ' + pkt.encode('hex')
        self.sock.send(pkt)
        print("[EAP]: Send Start Packet")
        self.last_start = time.time()
        self.state = 0

    def send_logoff(self):
        X_TYPE_START = 2
        pkt = self.make_ether_header() + self.make_8021x_header(X_TYPE_START, 0)
        length = len(pkt)
	pkt = pkt + '\x00' * (96 - length)
	print 'logoff pkt = ' + pkt.encode('hex')
        self.sock.send(pkt)
        print("[EAP]: Disconnect from Server")
        self.state = 0


    def handle(self):
        #定义EAP状态
        X_TYPE_EAP_PACKET = 0

        EAP_CODE_REQUEST = 1
        EAP_CODE_RESPONSE = 2
        EAP_CODE_SUCCESS = 3
        EAP_CODE_FAILURE = 4

        EAP_TYPE_IDENTITY = 1
        EAP_TYPE_MD5CHALLENGE = 4

        data = self.sock.recv(65535)
        if data[:1] != '\xff' :         #通过抓包数据分析，广播有大量ff的数据 都是无用数据，将他们屏蔽
	    print 'recv = ' + data.encode('hex')

        ether_dst, ether_src, ether_type = unpack('>6s6sH', data[:14])
        
        if self.pae_group_addr[:1] == '\xff':
            if ether_dst == self.hw_addr :
                self.pae_group_addr = ether_src
            else:
                self.pae_group_addr = ether_dst
            print self.pae_group_addr.encode('hex')
            

        #对接收的数据进行筛选处理
            
        # 802.1X 校验        
        a_8021x_ver, a_8021x_type, a_8021x_length = unpack('>BBH', data[14:18])
        if a_8021x_ver != 1 and a_8021x_type != 0:    
            print('[EAP]: 802.1X check failed: ver={} type={}'.format(
                a_8021x_ver, a_8021x_type))
            return

        #EAP长度检验
        eap_code, eap_id, eap_length = unpack('>BBH', data[18:22])
        if eap_length > len(data) - 18 or eap_length != a_8021x_length:
            print('[EAP]: EAP length check failed: len={} len(802.1X)={}'.format(
                eap_length, a_8021x_length))
            return

        #数据的分类处理


        #8021x 认证请求发起
        if self.state == 0:
            if eap_code == EAP_CODE_REQUEST and eap_length >= 5:
                eap_type = unpack('B', data[22:23])[0]
                if eap_type == EAP_TYPE_IDENTITY:
                    print("[EAP]: Request: Identify")
                    eap_pkt = self.make_eap_pkt(
                        EAP_CODE_RESPONSE, eap_id,
                        pack('B%ds' % len(self.username), EAP_TYPE_IDENTITY, self.username))
                    pkt = self.make_ether_header() + self.make_8021x_header(
                        X_TYPE_EAP_PACKET, len(eap_pkt))	
                    pkt += eap_pkt
                    pkt += '\x00\x44\x61'
                    length = len(pkt)
                    pkt += '\x00'*(96-length)
                    print '[EAP]: Response: Identify\n send = ' + pkt.encode('hex')
                    self.sock.send(pkt)
                    self.state = 1
            else:
                print("EAP check failed")


        #MD5验证
        if self.state <= 1:
            if eap_code == EAP_CODE_REQUEST and eap_length >= 5:
                eap_type = unpack('B', data[22:23])[0]
                if eap_type == EAP_TYPE_MD5CHALLENGE:
                    print("[EAP]: Request: MD5 Challenge")
                    eap_value_size = unpack('B', data[23: 24])[0]
                    if eap_value_size != eap_length - 10:
                        print('State 1 wrong MD5 challenge eap-Len: {}, value_len: {}'.format(
                            eap_length, eap_value_size))
                        return
                    challenge = data[24: 24 + eap_value_size]
                    response = md5(chr(eap_id) + self.password + challenge).digest()
                    pkt = self.make_ether_header()
                    extra = self.username 
                    eap_pkt = self.make_eap_pkt(EAP_CODE_RESPONSE, eap_id, pack(
                        'BB16s{}s'.format(len(extra)), EAP_TYPE_MD5CHALLENGE, 16, response, extra
                    ))
                    self.md5_load = '\x10' + response
                    pkt += self.make_8021x_header(X_TYPE_EAP_PACKET, len(eap_pkt))
                    pkt += eap_pkt
                    pkt += '\x00\x44\x61'
                    length = len(pkt)
                    pkt += '\x00' * (96 - length)
                    print len(pkt)
                    self.sock.send(pkt)

                    print("[EAP]: Md5 Challenge Response\n send = " + pkt.encode('hex'))
                    self.state = 2
                    return
            elif eap_code == EAP_CODE_FAILURE and eap_length == 4:
                print("[EAP]: Wrong identity")
                return
            else:
                print("[EAP]: EAP Identity Check failed")
                return

        #登陆验证
        if self.state == 2:
            if eap_code == EAP_CODE_SUCCESS and eap_length == 4:
                print("[EAP]: Login Success!")                
                self.udp_process = keepalive.UDPKeepAlive(self.username, self.password,
                                                         self.md5_load, Utils.get_ip_address(self.iface), self.hw_addr_text)
                self.udp_process.daemon = True
                self.udp_process.start()
                self.state = 10                
            else:
                print("[EAP]:Login Failed!")
                exit(1)

        if self.state == 10:
            if eap_code == EAP_CODE_REQUEST and eap_length >= 5:
                eap_type = unpack('B', data[22:23])[0]
                if data[:1] != '\x01' :
                    if eap_type == EAP_TYPE_IDENTITY:
                        eap_pkt = self.make_eap_pkt(
                            EAP_CODE_RESPONSE, eap_id,
                            pack('B%ds' % len(self.username), EAP_TYPE_IDENTITY, self.username))
                        pkt = self.make_ether_header() + self.make_8021x_header(
                            X_TYPE_EAP_PACKET, len(eap_pkt))
                        pkt += eap_pkt
                        pkt += '\x00\x44\x61'
                        length = len(pkt)
                        pkt += '\x00' * (96 - length) 
                        print 'EAp packet = ' + pkt.encode('hex')
                        self.sock.send(pkt)
                        self.sock.send(pkt)
            elif eap_code == EAP_CODE_FAILURE:
                print("[Critical]: EAP_Failure Captured")
                

    def run(self):
        for x in range(1):
            self.send_logoff()
            time.sleep(2)
        self.send_start()

        while True:
            r, w, x = select([self.sock], [], [self.sock])
            if x:
                raise Exception("socket Exception")
            self.handle()
            if time.time() - self.last_start and self.state == 0:
                self.send_start()
    

