package app;


import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.namednumber.ArpOperation;
import org.pcap4j.util.ByteArrays;

import java.util.ArrayList;
import java.util.Arrays;

public class packetInfoBuilder {

    static String buildInfo(Packet packet, String protocol){
        String buildinfo = "";
        switch(packet.getClass().getName()){
            case "org.pcap4j.packet.TcpPacket":
                TcpPacket tcpPacket = packet.get(TcpPacket.class);
                if(protocol!=null) {
                    switch (protocol) {
                        case "HTTP":
                            String tmp = "";
                            for (byte b : packet.getPayload().getRawData()) tmp += (char) b;
                            String version = tmp.substring(tmp.indexOf("HTTP/"), tmp.indexOf("HTTP/") + 9);
                            if (tmp.startsWith("GET")) return "GET * " + version;
                            else buildinfo = "NOTIFY * " + version;
                            break;
                        default:
                            buildinfo = protocol;
                            break;
                    }
                } else {
                    buildinfo = tcpPacket.getHeader().getSrcPort() + "->" + tcpPacket.getHeader().getDstPort() + " " +
                            getTcpFlags(tcpPacket);

                }
                break;
            case "org.pcap4j.packet.UdpPacket":
                UdpPacket udpPacket = packet.get(UdpPacket.class);
                if(protocol!=null){
                    switch(protocol){
                        case "SSDP":
                            String tmp = "";
                            for (byte b : packet.getPayload().getRawData()) tmp += (char) b;
                            String version = tmp.substring(tmp.indexOf("HTTP/"), tmp.indexOf("HTTP/") + 9);
                            if (tmp.startsWith("GET")) return "GET * " + version;
                            else buildinfo = "NOTIFY * " + version;
                            break;
                        default:
                            buildinfo = protocol;
                    }

                }else{
                    buildinfo = "Source Port: " + udpPacket.getHeader().getSrcPort().valueAsString() +
                            "Destination Port: " + udpPacket.getHeader().getDstPort().valueAsString();

                }
                break;
            case "org.pcap4j.packet.ArpPacket":
                ArpPacket.ArpHeader arpHeader = packet.get(ArpPacket.class).getHeader();
                if(arpHeader.getOperation().equals(ArpOperation.REQUEST))
                    buildinfo = "Who has " + arpHeader.getDstProtocolAddr() + "? Tell " + arpHeader.getSrcProtocolAddr();
                else if(arpHeader.getOperation().equals(ArpOperation.REPLY)){
                    buildinfo = arpHeader.getSrcProtocolAddr() + " belongs to " + arpHeader.getSrcHardwareAddr();
                }
                break;


        }

        return buildinfo;

    }

    static String resolveProtocol(Packet packet){
        ArrayList<String> hexArray = new ArrayList<>
                (Arrays.asList(ByteArrays.toHexString(packet.getRawData(), " ").split(" ")));
        String raw = "";
        for(byte b : packet.getRawData()) raw+=(char) b;

        if(raw.startsWith("NOTIFY") || raw.startsWith("GET")) {
            if (packet.getClass().getName().equals("org.pcap4j.packet.TcpPacket")) return "HTTP";
            else return "SSDP";
        }
        return "Unknown";
    }

    private static String getTcpFlags(TcpPacket packet){
        TcpPacket.TcpHeader header = packet.getHeader();
        String flags =  ("[" + (header.getAck()?"ACK, ":"") + (header.getUrg()?"URG, ":"") + (header.getPsh()?"PSH, ":"")
                + (header.getRst()?"RST, ":"") + (header.getSyn()?"SYN, ":"") + (header.getFin()?"FIN, ":""));
        return flags.substring(0, flags.length()-2)+"]";
    }
}

