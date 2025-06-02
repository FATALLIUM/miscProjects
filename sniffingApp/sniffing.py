from scapy.all import sniff;
from scapy.layers.inet import *;
import time;

def packetCheck(packet):
    if IP in packet:
        timeStamp = packet.time;
        localTime = time.localtime(timeStamp);
        strTime = time.strftime('%A, %d/%m/%y, %I:%M:%S %p', localTime);

        ipLayer = packet[IP];
        protocol = ipLayer.proto;
        pktLen = len(packet);
        ipVersion = packet.version;

        srcIp = ipLayer.src;
        srcPort = ipLayer.sport;

        dstIp = ipLayer.dst;
        dstPort = ipLayer.dport;

        protocolName = "";

        match protocol:
            case 1:
                protocolName = "ICMP";
            case 6:
                protocolName = "TCP";
            case 17:
                protocolName = "UDP";
            case 143:
                protocolName = "Ethernet";
            case _:
                protocolName = "Unknown protocol";

        print(f"Time: {strTime}\nIP version: {ipVersion}\nPacket length: {pktLen}");
        print(f"Protocol: {protocolName}");
        print("*" * 40);
        print(f"Source IP: {srcIp}\nSource protocol: {srcPort}\n\n");
        print(f"Destination IP: {dstIp}\nDestination protocol: {dstPort}");
        print("*" * 40);

def main():
    sniff(prn = packetCheck, filter = "ip", store = 0);

main();