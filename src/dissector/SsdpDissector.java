package dissector;


import app.packetPropertiesLayout;
import org.pcap4j.packet.Packet;

import java.util.ArrayList;

public class SsdpDissector extends AbstractDissector{

    @Override
    @SuppressWarnings("unchecked")
    public ArrayList<ValuePair<String, String>> dissect(Packet packet) {
        String raw = "";
        for(byte b : packet.getRawData()) raw+=(char)b;

        values.add(new ValuePair("Version", raw.substring(raw.indexOf("HTTP/"),raw.indexOf("HTTP/")+8)));
        values.add(new ValuePair("Request Method", "NOTIFY"));

        for(String s : raw.split("\n")){
            //If its the request string ignore it
            if(s.startsWith("NOTIFY")) continue;
            //filter out all of the garbage spacers and get the real data
            if(s.split(":").length>1) values.add(new ValuePair(s.split(":")[0], s.split(":")[1]));
        }
        return values;

    }

    @Override
    packetPropertiesLayout.protocol getProtocol() {
        return packetPropertiesLayout.protocol.SSDP;
    }
}
