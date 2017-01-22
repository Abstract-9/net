package dissector;

import app.packetPropertiesLayout;
import org.pcap4j.packet.Packet;

import java.util.ArrayList;

public abstract class AbstractDissector {

    ArrayList<ValuePair<String, String>> values = new ArrayList<>();
    Packet currentPacket;

    public abstract ArrayList<ValuePair<String, String>> dissect(Packet packet);

    ArrayList<ValuePair<String, String>> getValues() {
        return values;
    }

    Packet getCurrentPacket() {
        return currentPacket;
    }

    ValuePair getKey(String key){
        for(ValuePair v : values){
            if(v.getKey().equals(key)) return v;
        }
        return null;
    }

    abstract packetPropertiesLayout.protocol getProtocol();
}
