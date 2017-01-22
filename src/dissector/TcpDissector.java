package dissector;

import app.packetPropertiesLayout;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.util.ByteArrays;

import java.util.ArrayList;


public class TcpDissector extends AbstractDissector {

    @Override
    @SuppressWarnings("unchecked")
    public ArrayList<ValuePair<String, String>> dissect(Packet packet) {
        super.currentPacket = packet;
        TcpPacket.TcpHeader tcpHeader = packet.get(TcpPacket.class).getHeader();

        values.add(new ValuePair("Source Port", tcpHeader.getSrcPort().valueAsString()));
        values.add(new ValuePair("Destination Port",tcpHeader.getDstPort().valueAsString()));
        values.add(new ValuePair("Header Length", String.valueOf(tcpHeader.getRawData().length)));
        values.add(new ValuePair("Acknowledgement Number", String.valueOf(tcpHeader.getAcknowledgmentNumber())));
        values.add(new ValuePair("Urgent", String.valueOf(tcpHeader.getUrg())));
        values.add(new ValuePair("Acknowledgement", String.valueOf(tcpHeader.getAck())));
        values.add(new ValuePair("PSH", String.valueOf(tcpHeader.getPsh())));
        values.add(new ValuePair("RST", String.valueOf(tcpHeader.getRst())));
        values.add(new ValuePair("SYN", String.valueOf(tcpHeader.getSyn())));
        values.add(new ValuePair("FIN", String.valueOf(tcpHeader.getFin())));
        values.add(new ValuePair("Window Size", String.valueOf(tcpHeader.getWindow())));
        values.add(new ValuePair("Header CheckSum", "0x" + ByteArrays.toHexString(tcpHeader.getChecksum(), "")));
        return values;
    }

    @Override
    packetPropertiesLayout.protocol getProtocol() {
        return packetPropertiesLayout.protocol.Tcp;
    }
}
