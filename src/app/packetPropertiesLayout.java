package app;

import dissector.*;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.TextArea;
import org.pcap4j.packet.*;
import org.pcap4j.util.ByteArrays;


import java.util.ArrayList;
import java.util.Arrays;

public class packetPropertiesLayout {

    public enum protocol{
        HTTP ("Hypertext Transfer Protocol"),
        SSDP ("Simple Service Discovery Protocol"),
        Tcp  ("Transmission Control Protocol"),
        Udp  ("User Datagram Protocol"),
        Arp  ("Address Resolution Protocol"),
        IpV4 ("Internet Protocol Version 4"),
        IpV6 ("Internet Protocol Version 6");

        private final String longName;

        protocol(String longName){
            this.longName = longName;
        }

        String getLongName(){
            return this.longName;
        }
    }

    private ArrayList<ListView<String>> lists;
    private ArrayList<Label> labels;
    private ArrayList<AbstractDissector> dissectors;
    private EthernetPacket currentPacket;
    private ArrayList<String> packetTopology = new ArrayList<>();
    private PacketCell cell;
    private TextArea raw;

    packetPropertiesLayout(ArrayList<ListView<String>> lists, ArrayList<Label> labels, TextArea raw){
        this.lists=lists;
        this.labels=labels;
        this.raw=raw;
    }

    void generateLayout(Packet packet, PacketCell cell){
        for(ListView<String> l : lists) l.setItems(FXCollections.emptyObservableList());
        for (Label l : labels) l.setText("");

        packetTopology.clear();

        currentPacket = packet.get(EthernetPacket.class);
        this.cell = cell;

        generalProperties();
        firstProtocolProperties(currentPacket.getPayload());
        if(packetTopology.size()>2) {
            secondProtocolProperties(currentPacket.getPayload().getPayload());
            if(packetTopology.size()>3) {
                thirdProtocolProperties(currentPacket.getPayload().getPayload().getPayload());
            }
        }
        generateRaw();
    }

    private void generalProperties(){
        ObservableList<String> values = FXCollections.observableArrayList();
        //add various general information values to the list
        values.add("Frame Number: " + cell.getNum());
        values.add("Capture Time: " + cell.getCapTime().toString());
        values.add("Capture Interface: " + PacketCellFactory.getSniffer().getPnif().getName());
        values.add("Epoch Time: " + cell.getCapTime().getTime() + "ms");
        values.add("Frame Length: " + currentPacket.getRawData().length + " bytes");

        generateTopology();
        String topology = "Packet Topology: ";
        for(String s : packetTopology){
            if(packetTopology.get(packetTopology.size()-1).equals(s))topology+=s;
            else topology+=s + " -> ";
        }
        values.add(topology);

        values.add("Source MAC Address: " + currentPacket.getHeader().getSrcAddr());
        values.add("Destination MAC Address: " + currentPacket.getHeader().getDstAddr());
        lists.get(0).setItems(values);

    }

    private void firstProtocolProperties(Packet packet){
        AbstractDissector dissector = null;
        ObservableList<String> values = FXCollections.observableArrayList();
        switch(packetTopology.get(1)){
            case "IpV4":
                labels.get(0).setText(protocol.valueOf("IpV4").getLongName());
                dissector = new IpV4Dissector();
                break;
            case "Arp":
                labels.get(0).setText(protocol.valueOf("Arp").getLongName());
                dissector = new ArpDissector();
                break;
        }
        if(dissector!=null){
            for(ValuePair<String, String> v : dissector.dissect(packet)){
                values.add(v.getKey() + ": " + v.getValue());
            }
        }

        lists.get(1).setItems(values);
    }

    private void secondProtocolProperties(Packet packet){
        AbstractDissector dissector = null;
        ObservableList<String> values = FXCollections.observableArrayList();
        switch(packetTopology.get(2)) {
            case "Tcp":
                labels.get(1).setText(protocol.valueOf("Tcp").getLongName());
                dissector = new TcpDissector();
                break;
            case "Udp":
                UdpPacket.UdpHeader udpHeader = packet.get(UdpPacket.class).getHeader();
                labels.get(1).setText(protocol.valueOf("Udp").getLongName());
                dissector = new UdpDissector();
                break;
        }
        if(dissector!=null) {
            for (ValuePair<String, String> v : dissector.dissect(packet)) {
                values.add(v.getKey() + ": " +  v.getValue());
            }
        }
        lists.get(2).setItems(values);

    }

    private void thirdProtocolProperties(Packet packet){
        if(!packetTopology.get(3).equals("Unknown")){
            labels.get(2).setText(protocol.valueOf(packetTopology.get(3)).getLongName());
        }
    }

    private void generateTopology(){
        packetTopology.add(currentPacket.getClass().getName().substring(18).replace("Packet", ""));
        Packet tmpPacket = null;
        if(currentPacket.getPayload()!=null) tmpPacket = currentPacket.getPayload();
        if(tmpPacket!=null) {
            boolean moreLayers = true;
            while(moreLayers) {
                String layer = tmpPacket.getClass().getName().substring(18).replace("Packet", "");
                if(layer.equals("Unknown")) packetTopology.add(packetInfoBuilder.resolveProtocol(tmpPacket));
                else packetTopology.add(tmpPacket.getClass().getName().substring(18).replace("Packet", ""));
                if(tmpPacket.getPayload()!=null) tmpPacket = tmpPacket.getPayload();
                else moreLayers=false;
            }

        }
    }

    private void generateRaw(){
        String fillText = "";
        ArrayList<String> hexArray = new ArrayList<>(Arrays.asList(currentPacket.toHexString().split(" ")));
        String packetText = "";

        for(byte b : currentPacket.getRawData()){
            if(b<(byte)32 || b>(byte)127) packetText+=".";
            else packetText+=(char)b;
        }

        for(int i=1;i<hexArray.size()+1;i++){
            if(i!=0 && i%16==0) fillText+=hexArray.get(i-1)+"        " + packetText.substring(i-16,i-8) + "    " + packetText.substring(i-8,i) + "\n";
            else if(i!=0 && i%8==0) fillText+=hexArray.get(i-1)+"    ";
            else fillText+=hexArray.get(i-1)+" ";
        }
        raw.setText(fillText);
    }

}
