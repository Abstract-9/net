package dissector;

import app.packetPropertiesLayout;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.ByteArrays;

import java.util.ArrayList;

public class IpV4Dissector extends AbstractDissector {

    @Override
    @SuppressWarnings("unchecked")
    public ArrayList<ValuePair<String, String>> dissect(Packet packet) {
        currentPacket = packet;
        IpV4Packet.IpV4Header ipV4Header = packet.get(IpV4Packet.class).getHeader();

        values.add(new ValuePair("Version",  "0x0800"));
        values.add(new ValuePair("Source Address", ipV4Header.getSrcAddr().toString().substring(1)));
        values.add(new ValuePair("Destination Address", ipV4Header.getDstAddr().toString().substring(1)));
        values.add(new ValuePair("Header Length", String.valueOf(ipV4Header.getRawData().length)));
        values.add(new ValuePair("Total Length", String.valueOf(ipV4Header.getTotalLength())));

        if(ipV4Header.getDontFragmentFlag()) values.add(new ValuePair("Dont Fragment Flag", "true"));
        else{
            values.add(new ValuePair("Dont Fragment Flag", "false"));
            values.add(new ValuePair("More Fragments Flag", String.valueOf(ipV4Header.getMoreFragmentFlag())));
        }

        values.add(new ValuePair("Fragment Offset", String.valueOf(ipV4Header.getFragmentOffset())));
        values.add(new ValuePair("Time To Live", String.valueOf(ipV4Header.getTtl())));
        values.add(new ValuePair("Header Checksum", "0x" + ByteArrays.toHexString(ipV4Header.getHeaderChecksum(), "")));
        return values;
    }

    @Override
    packetPropertiesLayout.protocol getProtocol() {
        return packetPropertiesLayout.protocol.IPV4;
    }


}
