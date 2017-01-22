package dissector;


import app.packetPropertiesLayout;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Packet;

import java.util.ArrayList;

public class ArpDissector extends AbstractDissector{

    @Override
    @SuppressWarnings("unchecked")
    public ArrayList<ValuePair<String, String>> dissect(Packet packet) {
        super.currentPacket = packet;
        ArpPacket.ArpHeader arpHeader = packet.get(ArpPacket.class).getHeader();
        values.add(new ValuePair("Protocol", arpHeader.getProtocolType().valueAsString()));
        values.add(new ValuePair("Hardware Size", arpHeader.getHardwareAddrLengthAsInt()));
        values.add(new ValuePair("Protocol Size", arpHeader.getHardwareAddrLengthAsInt()));
        values.add(new ValuePair("Sender Hardware Address", arpHeader.getSrcHardwareAddr()));
        values.add(new ValuePair("Sender IP address", arpHeader.getSrcProtocolAddr().toString()));
        values.add(new ValuePair("Target Hardware Address", arpHeader.getDstHardwareAddr()));
        values.add(new ValuePair("Target IP address", arpHeader.getDstProtocolAddr().toString()));
        return values;
    }

    @Override
    packetPropertiesLayout.protocol getProtocol() {
        return packetPropertiesLayout.protocol.Arp;
    }
}
