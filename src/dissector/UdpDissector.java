package dissector;

import app.packetPropertiesLayout;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.util.ByteArrays;

import java.util.ArrayList;


public class UdpDissector extends AbstractDissector {

    @Override
    @SuppressWarnings("unchecked")
    public ArrayList<ValuePair<String, String>> dissect(Packet packet) {
        super.currentPacket = packet;
        UdpPacket.UdpHeader udpHeader = packet.get(UdpPacket.class).getHeader();

        values.add(new ValuePair("Source Port", udpHeader.getSrcPort().valueAsString()));
        values.add(new ValuePair("Destination Por", udpHeader.getDstPort().valueAsString()));
        values.add(new ValuePair("Header Length", String.valueOf(udpHeader.getLength())));
        values.add(new ValuePair("Header Checksum", "0x" +  ByteArrays.toHexString(udpHeader.getChecksum(), "")));
        return values;
    }

    @Override
    packetPropertiesLayout.protocol getProtocol() {
        return packetPropertiesLayout.protocol.Udp;
    }
}
