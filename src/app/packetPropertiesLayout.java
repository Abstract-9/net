package app;

import com.sun.istack.internal.Nullable;
import dissector.*;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.scene.control.Label;
import javafx.scene.control.ListView;
import javafx.scene.control.TextArea;
import org.pcap4j.packet.*;
import org.pcap4j.util.ByteArrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class packetPropertiesLayout {

    public enum protocol{
        HTTP ("Hypertext Transfer Protocol"),
        SSDP ("Simple Service Discovery Protocol"),
        TCP  ("Transmission Control Protocol"),
        UDP  ("User Datagram Protocol"),
        ARP  ("Address Resolution Protocol"),
        IPV4 ("Internet Protocol Version 4"),
        IPV6 ("Internet Protocol Version 6");

        private final String longName;

        protocol(String longName){
            this.longName = longName;
        }

        String getLongName(){
            return this.longName;
        }
    }

    public Map<protocol, Class> dissectorMap = new HashMap<>();

    private ArrayList<ListView<String>> lists;
    private ArrayList<Label> labels;
    private ArrayList<AbstractDissector> dissectors;
    private EthernetPacket currentPacket;
    private ArrayList<String> packetTopology = new ArrayList<>();
    private PacketCell cell;
    private TextArea raw;
    private Logger logger = LoggerFactory.getLogger(packetPropertiesLayout.class);

    packetPropertiesLayout(ArrayList<ListView<String>> lists, ArrayList<Label> labels, TextArea raw){
        this.lists=lists;
        this.labels=labels;
        this.raw=raw;
        try {
            Path path = Paths.get(getClass().getProtectionDomain().getCodeSource().getLocation().getPath()
                    .substring(3)+"\\dissector");
            //Loads all dissectors in the dissector package
            Files.walkFileTree(path, visitor);
        }catch (Exception e){
            logger.error("ERROR LOADING DISSECTORS! DISSECTOR FUNCTIONALITY LOST!");
            logger.debug(e.getMessage());
        }
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
        AbstractDissector dissector = loadDissector(protocol.valueOf(packetTopology.get(1).toUpperCase()));
        ObservableList<String> values = FXCollections.observableArrayList();
        if(dissector!=null){
            for(ValuePair<String, String> v : dissector.dissect(packet)){
                values.add(v.getKey() + ": " + v.getValue());
            }
        }
        labels.get(0).setText(protocol.valueOf(packetTopology.get(1).toUpperCase()).getLongName());
        lists.get(1).setItems(values);
    }

    private void secondProtocolProperties(Packet packet){
        if(!packetTopology.get(2).equals("Unknown")) {
            AbstractDissector dissector = loadDissector(protocol.valueOf(packetTopology.get(2).toUpperCase()));
            ObservableList<String> values = FXCollections.observableArrayList();
            if (dissector != null) {
                for (ValuePair<String, String> v : dissector.dissect(packet)) {
                    values.add(v.getKey() + ": " + v.getValue());
                }
            }
            labels.get(1).setText(protocol.valueOf(packetTopology.get(2).toUpperCase()).getLongName());
            lists.get(2).setItems(values);
        }
    }

    private void thirdProtocolProperties(Packet packet){
        if(!packetTopology.get(3).equals("Unknown")) {
            AbstractDissector dissector = loadDissector(protocol.valueOf(packetTopology.get(3).toUpperCase()));
            ObservableList<String> values = FXCollections.observableArrayList();
            if (dissector != null) {
                for (ValuePair<String, String> v : dissector.dissect(packet)) {
                    if(v.getValue()!=null)values.add(v.getKey() + ": " + v.getValue());
                    else values.add(v.getKey());
                }
            }
            labels.get(2).setText(protocol.valueOf(packetTopology.get(3).toUpperCase()).getLongName());
            lists.get(3).setItems(values);
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

    @Nullable
    private AbstractDissector loadDissector(protocol protocol){
        AbstractDissector dissector;
        try {
            return ((AbstractDissector) dissectorMap.get(protocol).newInstance());
        }catch(Exception e){
            logger.error("DISSECTOR INSTANTIATION FAILED!");
            logger.debug("ATTEMPTED TO INSTANTIATE: " + protocol.getLongName());
            logger.debug("ERROR: " + e.getMessage());
        }
        return null;
    }

    private SimpleFileVisitor<Path> visitor = new SimpleFileVisitor<Path>(){
        @Override
        public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
            if(!file.getFileName().toString().equals("AbstractDissector.class") && !file.getFileName().toString().equals("ValuePair.class")) {
                try {
                    dissectorMap.put(protocol.valueOf(file.getFileName().toString().replace("Dissector.class", "").toUpperCase()),
                            Class.forName("dissector." + file.getFileName().toString().replace(".class", "")));
                    logger.info("Loaded dissector: " + file.getFileName().toString());
                }catch (ClassNotFoundException e){
                    logger.error("UNABLE TO FIND CLASS " + file.getFileName().toString()
                            + " LIMITED DISSECTOR FUNCTIONALITY!");
                    logger.debug(e.getMessage());
                }
            }
            return FileVisitResult.CONTINUE;
        }
    };

}
