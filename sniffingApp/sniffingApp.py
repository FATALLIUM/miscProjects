from kivy.app import App;
from kivy.uix.gridlayout import GridLayout;
from kivy.uix.label import Label;
from kivy.uix.button import Button;
from kivy.uix.textinput import TextInput;
from kivy.uix.scrollview import ScrollView;
from kivy.clock import Clock;

from scapy.all import sniff;
from scapy.layers.inet import *;
import time;

layout = GridLayout(cols = 1, spacing = 10, size_hint_y = None);

class SniffingApp(GridLayout):
    def __init__(self, **kwargs):
        super(SniffingApp, self).__init__(**kwargs);
        self.rows = 4;
        self.sniffing = False;
        self.packetBuffer = [];

        self.add_widget(Label(text = 'Sniffing App', size_hint_y = None, width = 500));

        self.outputArea = TextInput(
            text='Packet Monitor Ready...\n\n',
            multiline = True,
            readonly = True,
            size_hint_y = None,
            height = 2000
        );

        scroll = ScrollView(size_hint = (None, None), size = (1000, 500));
        scroll.add_widget(self.outputArea);
        self.add_widget(scroll);

        self.controlButton = Button(
            text = 'Start Monitoring',
            size_hint_y = None,
            height = 50
        );
        self.controlButton.bind(on_press = self.toggleSniffing);
        self.add_widget(self.controlButton);

        self.statusLabel = Label(
            text = 'Status: Ready',
            size_hint_y = None,
            height = 30
        );
        self.add_widget(self.statusLabel);
    
        Clock.schedule_interval(self.updateDisplay, 0.5);
    
    def toggleSniffing(self, inst):
        self.sniffing = not self.sniffing;
        if self.sniffing:
            self.controlButton.text = 'Stop Monitoring';
            self.statusLabel.text = 'Status: Monitoring (Simulated)';
            self.outputArea.text += 'Started packet monitoring...\n\n';

            Clock.schedule_interval(self.sniffPackets, 0.1);
        else:
            self.controlButton.text = 'Start Monitoring';
            self.statusLabel.text = 'Status: Stopped';
            self.outputArea.text += 'Stopped packet monitoring.\n\n';

    def sniffPackets(self, dt):
        if not self.sniffing:
            Clock.unschedule(self.sniffPackets);
            return False;
        
        sniff(prn = self.packetCallback, filter = "ip", timeout = 0.1, store = 0);
        return True;

    def packetCallback(self, packet):
        if not self.sniffing:
            return;
    
        self.packetBuffer.append(packet);
    
    def updateDisplay(self, dt):
        if not self.packetBuffer:
            return;

        for packet in self.packetBuffer:
            self.packetCheck(packet);
        
        self.packetBuffer.clear();

    def packetCheck(self, packet):
        pktInfo = '';

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

            pktInfo = (f"\nTime: {strTime}\nIP version: {ipVersion}\nPacket length: {pktLen}");
            pktInfo += (f"\nProtocol: {protocolName}");
            pktInfo += (f"\nSource IP: {srcIp}\nSource protocol: {srcPort}\n\n");
            pktInfo += (f"\nDestination IP: {dstIp}\nDestination protocol: {dstPort}");

            self.outputArea.text += pktInfo;

            if len(self.outputArea.text) > 2000:
                self.outputArea.text = self.outputArea.text[-1500:];

class MyApp(App):
    def build(self):
        return SniffingApp();

if __name__ == '__main__':
    MyApp().run();



