package dissector;

import org.pcap4j.packet.Packet;

import java.util.ArrayList;

abstract class AbstractDissector{

    private ArrayList<ValuePair> values = new ArrayList<>();
    private Packet currentPacket;


    abstract ArrayList<ValuePair> dissect(Packet p);


    ArrayList<ValuePair> getValues(){
        return values;
    }

    Packet getCurrentPacket(){
        return currentPacket;
    }







}
