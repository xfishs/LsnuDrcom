# coding: utf-8
import LsnuDrcom
import time

# CONFIG

username = "88888"
password = "88888"
iface = 'eth0.2'  #路由网卡名称

# CONFIG_END


if __name__ == '__main__':
    dr = LsnuDrcom.DrComSupplicant(iface, username, password)
    try:
        dr.run()
    except KeyboardInterrupt:
        print("Killing~")
        if dr.udp_process:
            dr.udp_process.should_listen = False
        dr.send_logoff()
        time.sleep(2)
