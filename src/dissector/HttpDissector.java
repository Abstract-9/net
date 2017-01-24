package dissector;

import app.packetPropertiesLayout;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Method;
import java.util.ArrayList;


public class HttpDissector extends AbstractDissector {

    private Logger logger = LoggerFactory.getLogger(HttpDissector.class);

    @Override
    @SuppressWarnings("unchecked")
    public ArrayList<ValuePair<String, String>> dissect(Packet packet) {
        String raw = "";
        for(byte b : packet.getRawData()) raw+=(char)b;

        values.add(new ValuePair("Version", raw.substring(raw.indexOf("HTTP/"),raw.indexOf("HTTP/")+8)));

        String httpMethod="";
        if(raw.startsWith("GET")) httpMethod="GET";
        else if(raw.startsWith("POST")) httpMethod="POST";
        else if(raw.startsWith("HEAD")) httpMethod="HEAD";
        else if(raw.startsWith("DELETE")) httpMethod="DELETE";
        else if(raw.startsWith("TRACE")) httpMethod="TRACE";
        else if(raw.startsWith("CONNECT")) httpMethod="CONNECT";
        else if(raw.startsWith("OPTIONS")) httpMethod="OPTIONS";
        values.add(new ValuePair("HTTP Request Method", httpMethod));

        for(String s : raw.split("\n")){
            if(s.startsWith(httpMethod)) continue;
            if(s.split(":").length>1) values.add(new ValuePair<>(s.split(":")[0], s.split(":")[1]));
        }
        return values;
    }

    @Override
    packetPropertiesLayout.protocol getProtocol() {
        return packetPropertiesLayout.protocol.HTTP;
    }

    private void get(){

    }

    private void head(){

    }

    private void post(){

    }

    private void delete(){

    }

    private void trace(){

    }

    private void connect(){

    }

    private void options(){

    }
}
