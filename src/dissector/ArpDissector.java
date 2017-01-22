package dissector;


import org.pcap4j.packet.Packet;

import java.util.ArrayList;

public class ArpDissector extends AbstractDissector{
    @Override
    ArrayList<ValuePair> dissect(Packet p) {
        return null;
    }
}
