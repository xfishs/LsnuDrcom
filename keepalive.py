# -*- coding: utf-8 -*-

from threading import Thread
import socket
import time
import random
import binascii
from select import select
import struct

DRCOM_RESPONSE_FOR_ALIVE = '\x02'
DRCOM_RESPONSE_INFO = '\x04'
DRCOM_MISC_TYPE_2 = '\x02'
DRCOM_MISC_TYPE_4 = '\x04'



class UDPConnectionManager(Thread):
    def __init__(self, udp_delegate):
        Thread.__init__(self)
        self.udp_delegate = udp_delegate
        self.challenge_res = 0

    def wait_to_misc_loop(self):
        time.sleep(2)
        while self.udp_delegate.state == 2:
            if self.challenge_res < 3:
                print("[!!UDP]: Resend CRC Response")
                self.udp_delegate.send_udp_computerinfo(self.udp_delegate.current_crc_load)
                self.challenge_res += 1
                time.sleep(2)
            else:
                print("[!!UDP]: Try send Keep-Alive")
                self.udp_delegate.update_udp_misc1()
                self.udp_delegate.send_udp_misc1()
                return

    def run(self):
        self.wait_to_misc_loop()

class UDPKeepAlive(Thread):
    def __init__(self, username, password, md5_load, ip, mac):
        Thread.__init__(self)
        self.username = username
        self.password = password
        self.md5_load = md5_load
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.DST_ADDRESS = ("10.10.0.100", 61440)
        self.DST_IP = self.DST_ADDRESS[0]
        self.DST_IP_HEX = socket.inet_aton(self.DST_IP)
        self.DST_PORT = self.DST_ADDRESS[1]
        self.MY_IP = ip
        self.MY_IP_HEX = socket.inet_aton(self.MY_IP)
        self.MY_MAC = mac
        self.MY_MAC_HEX = binascii.a2b_hex(self.MY_MAC.replace(':', ''))
        try:
	    self.udp_sock.bind((self.MY_IP, self.DST_PORT))
	except Exception,e:
	    print e
        # state
        self.is_init_done = False
        self.should_listen = True
        # attributes
        self.drcom_pkt_id = 0
        self.p_udp_misc1 = ""
        self.p_udp_misc3 = ""
        self.misc_random_4bytes = ''  # misc type 1和type 3都要用到
        self.crc_8byte_for_244byte_info = ''  # 244byte和u38 alive都要用到
        self.state = 0
        self.current_crc_load = ''
        self.u244info = ''
        self.udp_manager = UDPConnectionManager(self)
        self.udp_manager.daemon = True
        self.keep_alive_info2 = None

    def run(self):
        print("[UDP]: Start to udp keep-alive")
        self.send_udp_start()
        self.listen()

    def listen(self):
        try:
            while self.should_listen:
                r, w, x = select([self.udp_sock], [], [self.udp_sock])
                if x:
                    raise Exception("socket Exception")
                self.handle()
        except KeyboardInterrupt:
            print("End udp thread")
            exit()

    def restart(self):
        self.udp_manager = UDPConnectionManager(self)
        self.state = 0
        self.should_listen = True
        self.send_udp_start()
        self.listen()

    def send_udp(self, data, dst_addr):
        self.udp_sock.sendto(data, dst_addr)

    def crc_misc_type_3(self, data):
        temp = 0
        for i in range(len(data))[::2]:
            temp ^= struct.unpack('H', data[i:i + 2])[0]
        result = struct.pack('I', temp * 711)
        return result

    def _crc_drcom(self, data):  # 由crc_drcom_info_hostname()调用
        result = 0
        for i in range(0, 244>>2, 4):
            ee = data[i:i + 4]
            result ^= struct.unpack('<I', ee)[0]
            result &= 0xFFFFFFFF
        return result

    def crc_drcom_info_hostname(self, data):  # 外部调用的是这个函数
        crc = (self._crc_drcom(data) * 19680126) & 0xFFFFFFFF
        return struct.pack('<I', crc)  # 大小端反过来

    def send_udp_start(self):  
        self.send_udp('\x07\x00\x08\x00\x01\x00\x00\x00', self.DST_ADDRESS)
        print '[UDP]: DrCOM Client: Send request alive.'

    def send_udp_computerinfo(self, load):
        self.send_udp(load, self.DST_ADDRESS)
        print '[UDP]: DrCOM Client: Send information.'

    def send_udp_misc1(self):
        self.send_udp(self.p_udp_misc1, self.DST_ADDRESS)
        print '[UDP]: DrCOM Client: Send misc type 1'

    def send_udp_misc3(self):
        self.send_udp(self.p_udp_misc3, self.DST_ADDRESS)
        print '[UDP]: DrCOM Client: Send misc type 3'

    def udp_38_crc(self):
        ee = self.u244info[1:2] + '\x00'
        aa = struct.unpack('<h',ee)[0] << 1
        if aa >= 128 :
            aa |= 1
        bb = struct.pack('<I',aa)[:1]
        ee = self.u244info[2:3] + '\x00'
        temp = struct.unpack('<h',ee)[0]
        cc = temp >> 1
        if temp % 2 != 0 :
            cc |= 128
        dd = struct.pack('<I',cc)[:1]
        return  self.u244info[0:1]+bb+dd
            
    
    def send_udp_38byte_alive(self):
        udp_crc_38 = self.udp_38_crc()
        foo = struct.pack('H',int(time.time())%0xFFFF)
        try:
            load = '\xff' + self.crc_8byte_for_244byte_info + self.md5_load[5:17] + 3 * '\x00'\
                + '\x44\x72\x63\x6f\x0a\x0a\x00\x64'+udp_crc_38[0:2]+ self.MY_IP_HEX + '\x01'+udp_crc_38[2:3]+foo
        except:
            print("[Critical]: Server Reject Due to auth left in server, retry in few minutes")
            exit(1)

        self.send_udp(load, self.DST_ADDRESS)
        print 'u38 = ' +load.encode('hex')
        print '[UDP]: DrCOM Client: Send alive per 12s'

    def request_unknown_content(self):
        self.misc_random_4bytes = chr(random.randint(0, 255)) + chr(random.randint(0, 255)) + \
                             chr(random.randint(0, 255)) + chr(random.randint(0, 255))  
        self.p_udp_misc1 = '\x07' + chr(self.drcom_pkt_id%256) + '\x28\x00\x0b\x01\x0f\x27' + self.misc_random_4bytes + 28 * '\x00'
        self.drcom_pkt_id += 1  

    def update_udp_misc1(self, current_random_bytes=False):
        self.misc_random_4bytes = chr(random.randint(0, 255)) + chr(random.randint(0, 255)) 
        if self.drcom_pkt_id == 0 :            
            self.p_udp_misc1 = '\x07' + chr(self.drcom_pkt_id%256) + '\x28\x00\x0b\x01\x0f\x27' + self.misc_random_4bytes + 30 * '\x00'
            print 'first u40 = ' + self.p_udp_misc1.encode('hex')
        else:
            self.p_udp_misc1 = '\x07' + chr(self.drcom_pkt_id%256) + '\x28\x00\x0b\x01\xdc\x02' + self.misc_random_4bytes + 30 * '\x00'
            print 'u40 = ' + self.p_udp_misc1.encode('hex')
        self.drcom_pkt_id += 1  

    def update_udp_misc3(self, former):
        temp = '\x07' + chr(self.drcom_pkt_id%256) + '\x28\x00\x0b\x03\xdc\x02' + \
               self.misc_random_4bytes + 14 * '\x00' + 4 * '\x00' + self.MY_IP_HEX + 8 * '\x00' 
        crc = self.crc_misc_type_3(temp)
        self.p_udp_misc3 = '\x07' + chr(self.drcom_pkt_id%256) + '\x28\x00\x0b\x03\xdc\x02' + \
                           self.misc_random_4bytes + 6 * '\x00' + former + 4 * '\x00' + crc + self.MY_IP_HEX + 8 * '\x00'
        print 'u40 = ' + self.p_udp_misc3.encode('hex')
        self.drcom_pkt_id += 1  

    def alive_per_12s(self):
        time.sleep(9)  
        self.send_udp_38byte_alive()
        time.sleep(3)  
        self.update_udp_misc1()  
        self.send_udp_misc1()

    def handle(self):
        data, addr = self.udp_sock.recvfrom(2048)
        print("receive udp {} from {} len: {}".format(data.encode("hex"), addr, len(data)))
        if addr != self.DST_ADDRESS:
            return
        if len(data) == 272:
            self.update_udp_misc1()
            self.send_udp_misc1()
        elif len(data) == 48 and data[:1] =='\x07':
            self.u244info = data[24:26] + data[31:32]
        elif addr[1] == self.DST_PORT and data[4] == DRCOM_RESPONSE_FOR_ALIVE:
            print("[UDP]: DrCOM: Response for alive!")
            challenge_seed = data[8:12]            
            udp_244byte_info = '\x07\x01\xf4\x00\x03\x0a' + self.MY_MAC_HEX + self.MY_IP_HEX + '\x03\x22\x00\x1f' + \
                               challenge_seed + '\xc7\x2f\x31\x01\x7e\x00\x00\x00' + self.username
            length = len(udp_244byte_info)
            if len(self.username) < 15:
                udp_244byte_info += '\x00'*(244 - length)
            else:
                udp_244byte_info += '\x00'*(248 - length)
            self.crc_8byte_for_244byte_info = self.crc_drcom_info_hostname(udp_244byte_info)  # 马上计算crc 之后回填
            load = '\x07\x01\xf4\x00\x03\x0a' + self.MY_MAC_HEX + self.MY_IP_HEX + '\x03\x22\x00\x1f' + \
                    challenge_seed + self.crc_8byte_for_244byte_info + 4 * '\x00' + self.username 
            if len(self.username) < 15:
                load += '\x00'*(248 - length)
            else:
                load += '\x00'*(248 - length) 
            self.current_crc_load = load
            self.send_udp_computerinfo(load)
            self.state = 2
            self.udp_manager.start()

        elif addr[1] == self.DST_PORT and (data[4] == DRCOM_RESPONSE_INFO or data[5] == '\x06'):
            print("[UDP]: DrCOM Server: Response Info, send misc")
            time.sleep(random.uniform(1, 1.2))
            # so here we need keep_alive_2
            info_2 = [0 for _ in range(16)]
            info_1 = data[16:]
            for x in range(16):
                info_2[x] = ((ord(info_1[x]) << (x & 7)) + (ord(info_1[x]) >> (8 - (x & 7)))) % 256
            keep_alive2 = "".join(["{:02X}".format(x) for x in info_2])
            self.keep_alive_info2 = keep_alive2.decode("hex")
            print("[Important]: Keep-Alive info 2: {}".format(self.keep_alive_info2.encode("hex")))
            self.update_udp_misc1()
            self.send_udp_misc1()
            self.is_init_done = True
            self.state = 4

        elif addr[1] == self.DST_PORT and data[5] == DRCOM_MISC_TYPE_2:
            print("[UDP]: DrCOM Server: MISC 2 data: {}".format(data[16: 20].encode("hex")))
            self.update_udp_misc3(data[16: 20])
            self.send_udp_misc3()

        elif addr[1] == self.DST_PORT and data[5] == DRCOM_MISC_TYPE_4:
            print("[UDP]: DrCOM Server: MISC 4")
            self.alive_per_12s()

