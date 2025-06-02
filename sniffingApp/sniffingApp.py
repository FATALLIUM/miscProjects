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

class SniffingApp(GridLayout):
    def __init__(self, **kwargs):
        super(SniffingApp, self).__init__(**kwargs);
        self.rows = 4;
        self.sniffing = False; # toggle bool for start/stopping program.
        self.packetBuffer = []; # packet buffer for keeping track of packets.

        # title label
        self.add_widget(Label(text = 'Sniffing App', size_hint_y = None, width = 500));

        # widget where packet info will be printed.
        self.outputArea = TextInput(
            text='Packet Monitor Ready...\n\n',
            multiline = True,
            readonly = True,
            size_hint_y = None,
            height = 2000
        );

        # widget allows user scrolling.
        scroll = ScrollView(size_hint = (None, None), size = (1000, 500));
        scroll.add_widget(self.outputArea);
        self.add_widget(scroll);

        # widget button where user will click to toggle program.
        self.controlButton = Button(
            text = 'Start Monitoring',
            size_hint_y = None,
            height = 50
        );
        self.controlButton.bind(on_press = self.toggleSniffing); # bind calls toggleSniffing to change sniffing bool.
        self.add_widget(self.controlButton);

        # label status of whether program is sniffing or not.
        self.statusLabel = Label(
            text = 'Status: Ready',
            size_hint_y = None,
            height = 30
        );
        self.add_widget(self.statusLabel);

        # regularly updates outputArea text using Clock.
        Clock.schedule_interval(self.updateDisplay, 0.5);
    
    def toggleSniffing(self, inst):
        # changes sniffing bool to its opposite.
        self.sniffing = not self.sniffing;

        # change text in widgets depending on sniffing bool.
        if self.sniffing:
            self.controlButton.text = 'Stop Monitoring';
            self.statusLabel.text = 'Status: Monitoring (Simulated)';
            self.outputArea.text += 'Started packet monitoring...\n\n';

            # calls sniffPackets in .1 second intervals using Clock.
            Clock.schedule_interval(self.sniffPackets, 0.1);
        else:
            self.controlButton.text = 'Start Monitoring';
            self.statusLabel.text = 'Status: Stopped';
            self.outputArea.text += 'Stopped packet monitoring.\n\n';

    def sniffPackets(self, dt):
        # if not sniffing, stop sniffing packets (unschedule).
        if not self.sniffing:
            Clock.unschedule(self.sniffPackets);
            return False;
        
        # call scapy sniff to store packets in packetBuffer using packetCallback.
        # filters IP layer with timeout of .1. 
        # does not store packet info.
        sniff(prn = self.packetCallback, filter = "ip", timeout = 0.1, store = 0);
        return True;

    def packetCallback(self, packet):
        if not self.sniffing:
            return;
        # append packet to packetBuffer.
        self.packetBuffer.append(packet);
    
    def updateDisplay(self, dt):
        if not self.packetBuffer:
            return;
        # packetCheck is called with argument packet.
        for packet in self.packetBuffer:
            self.packetCheck(packet);
        
        # clear packetBuffer after finished checking.
        self.packetBuffer.clear();

    def packetCheck(self, packet):
        pktInfo = '';

        if IP in packet:
            # retrieving readable timestamps.
            timeStamp = packet.time;
            localTime = time.localtime(timeStamp);
            strTime = time.strftime('%A, %d/%m/%y, %I:%M:%S %p', localTime);

            # retrieving packet info.
            ipLayer = packet[IP];
            protocol = ipLayer.proto;
            pktLen = len(packet);
            ipVersion = packet.version;

            # retrieving src and dst IPs.
            srcIp = ipLayer.src;
            dstIp = ipLayer.dst;

            # retrieving src and dst protocols if possible.
            srcPort = getattr(ipLayer, 'sport', 'N/A');
            dstPort = getattr(ipLayer, 'dport', 'N/A');

            protocolName = "";

            # initiialize protocolName with match-case.
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

            # concatenate packet info.
            pktInfo = (f"\nTime: {strTime}\nIP version: {ipVersion}\nPacket length: {pktLen}");
            pktInfo += (f"\nProtocol: {protocolName}");
            pktInfo += (f"\nSource IP: {srcIp}\nSource protocol: {srcPort}\n\n");
            pktInfo += (f"\nDestination IP: {dstIp}\nDestination protocol: {dstPort}");

            # add packet info to outputArea.
            self.outputArea.text += pktInfo;

            # make sure outputArea length doesn't go crazy.
            if len(self.outputArea.text) > 2000:
                self.outputArea.text = self.outputArea.text[-1500:];

class MyApp(App):
    def build(self):
        return SniffingApp();

if __name__ == '__main__':
    MyApp().run();



