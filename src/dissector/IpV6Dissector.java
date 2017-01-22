package dissector;

import app.packetPropertiesLayout;
import org.pcap4j.packet.Packet;

import java.util.ArrayList;

/**
 * Created by Logan on 1/21/2017.
 */
public class IpV6Dissector extends AbstractDissector {
    @Override
    public ArrayList<ValuePair<String, String>> dissect(Packet packet) {
        return null;
    }

    @Override
    packetPropertiesLayout.protocol getProtocol() {
        return null;
    }
}
