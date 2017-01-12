package sniffer;


import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapNetworkInterface;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;

public class netInterface {

    private ArrayList<InetAddress> inetAddrs = new ArrayList<>();
    private String name = null, displayName = null;

    //Constructors

    public netInterface(String name, String displayName, ArrayList<InetAddress> inetaddrs){
        this.name = name;
        this.displayName = displayName;
        this.inetAddrs.addAll(inetaddrs);
    }

    public netInterface(PcapNetworkInterface pcapNif, NetworkInterface nif){
        if(pcapNif!=null){
            name=pcapNif.getName();
            for(PcapAddress addr : pcapNif.getAddresses()) inetAddrs.add(addr.getAddress());
        }
        if(nif!=null){
            displayName = nif.getDisplayName();
        }
    }

    //Public Methods

    public netInterface setName(String name){
        this.name = name;
        return this;
    }

    public netInterface setDisplayName(String displayName){
        this.displayName = displayName;
        return this;
    }

    public String getDisplayName(){
        return displayName;
    }

    public String getName(){
        return name;
    }

    public netInterface addAddress(InetAddress addr){
        this.inetAddrs.add(addr);
        return this;
    }

    public ArrayList<InetAddress> getAddresses(){
        return this.inetAddrs;
    }

}
