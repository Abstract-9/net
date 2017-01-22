package dissector;

import app.packetPropertiesLayout;
import org.pcap4j.packet.Packet;

import java.util.ArrayList;


public class HttpDissector extends AbstractDissector {

    @Override
    @SuppressWarnings("unchecked")
    public ArrayList<ValuePair<String, String>> dissect(Packet packet) {
        String raw = "";
        for(byte b : packet.getRawData()) raw+=b;

        values.add(new ValuePair("Version", raw.substring(raw.indexOf("HTTP/"),raw.indexOf("HTTP/")+8)));

        return values;
    }

    @Override
    packetPropertiesLayout.protocol getProtocol() {
        return packetPropertiesLayout.protocol.HTTP;
    }
}
