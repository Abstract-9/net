package app;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.TextArea;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.Packet;


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
        currentPacket = packet.get(EthernetPacket.class);
        this.cell = cell;
        generalProperties();
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

        if(packetTopology.isEmpty()) generateTopology();
        String topology = "Packet Topology: ";
        for(String s : packetTopology){
            if(packetTopology.get(packetTopology.size()-1).equals(s))topology+=s;
            else topology+=s + " -> ";
        }
        values.add(topology);
        lists.get(0).setItems(values);

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
        ArrayList<String> hexArray = new ArrayList<>(Arrays.asList(currentPacket.toHexString().split(" ")));
        String text = currentPacket.toString();
        for(int i=0;i<hexArray.size();i++){

        }
    }

}
