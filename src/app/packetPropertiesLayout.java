package app;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.TextArea;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.util.ByteArrays;


import java.util.ArrayList;
import java.util.Arrays;

class packetPropertiesLayout {

    private ArrayList<ListView<String>> lists;
    private ArrayList<Label> labels;
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
        secondProtocolProperties(currentPacket.getPayload().getPayload());
        thirdProtocolProperties(currentPacket.getPayload().getPayload().getPayload());
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
        ObservableList<String> values = FXCollections.observableArrayList();
        switch(packetTopology.get(1)){
            case "IpV4":
                labels.get(0).setText("Internet Protocol Version 4");
                IpV4Packet.IpV4Header ipV4Header = packet.get(IpV4Packet.class).getHeader();
                values.add("Version: 0x0800");
                values.add("Source Address:" + ipV4Header.getSrcAddr().toString().substring(1));
                values.add("Destination Address: " + ipV4Header.getDstAddr().toString().substring(1));
                values.add("Header Length: " + ipV4Header.getRawData().length);
                values.add("Total Length: " + ipV4Header.getTotalLength());

                if(ipV4Header.getDontFragmentFlag()) values.add("Dont Fragment Flag: true");
                else{
                    values.add("Dont Fragment Flag: false");
                    values.add("More Fragments Flag: " + ipV4Header.getMoreFragmentFlag());
                }

                values.add("Fragment Offset: " + ipV4Header.getFragmentOffset());
                values.add("Time To Live: " + ipV4Header.getTtl());
                values.add("Payload: " + packetTopology.get(2));
                values.add("Header Checksum: 0x" + ByteArrays.toHexString(ipV4Header.getHeaderChecksum(), ""));
                break;
        }
        lists.get(1).setItems(values);
    }

    private void secondProtocolProperties(Packet packet){
        ObservableList<String> values = FXCollections.observableArrayList();
        switch(packetTopology.get(2)){
            case "Tcp":
                TcpPacket.TcpHeader tcpHeader = packet.get(TcpPacket.class).getHeader();
                labels.get(1).setText("Transmission Control Protocol");
                values.add("Source Port: " + tcpHeader.getSrcPort());
                values.add("Destination Port: " + tcpHeader.getDstPort());
                values.add("Header Length: " + tcpHeader.getRawData().length);
                values.add("Acknowledgement Number: " + tcpHeader.getAcknowledgmentNumber());
                values.add("Urgent: " + tcpHeader.getUrg());
                values.add("Acknowledgement: " + tcpHeader.getAck());
                values.add("Push: " + tcpHeader.getPsh());
                values.add("Reset: " + tcpHeader.getRst());
                values.add("SYN: " + tcpHeader.getSyn());
                values.add("FIN: " + tcpHeader.getFin());
                values.add("Window Size: " + tcpHeader.getWindow());
                values.add("Header CheckSum: 0x" + ByteArrays.toHexString(tcpHeader.getChecksum(), ""));
        }
        lists.get(2).setItems(values);

    }

    private void thirdProtocolProperties(Packet packet){

    }

    private void generateTopology(){
        packetTopology.add(currentPacket.getClass().getName().substring(18).replace("Packet", ""));
        Packet tmpPacket = null;
        if(currentPacket.getPayload()!=null) tmpPacket = currentPacket.getPayload();
        if(tmpPacket!=null) {
            boolean moreLayers = true;
            while(moreLayers) {
                packetTopology.add(tmpPacket.getClass().getName().substring(18).replace("Packet", ""));
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
            if(i!=0 && i%16==0) fillText+=hexArray.get(i-1)+"        " + packetText.substring(i-16,i-8) + "    " + packetText.substring(i-8,i-1) + "\n";
            else if(i!=0 && i%8==0) fillText+=hexArray.get(i-1)+"    ";
            else fillText+=hexArray.get(i-1)+" ";
        }
        raw.setText(fillText);
    }

}
