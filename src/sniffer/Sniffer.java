package sniffer;

import com.sun.istack.internal.Nullable;
import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import java.net.InetAddress;
import java.net.UnknownHostException;

public class Sniffer {

    private static InetAddress local;
    private static PcapHandle handle;
    private static Logger logger = LoggerFactory.getLogger(Sniffer.class);
    static Packet currentPacket;

    public Sniffer(PcapNetworkInterface pnif, boolean init){
        if(init) init(pnif);
    }


    public void init(PcapNetworkInterface pnif){

        logger.info("Initializing Sniffer");

        logger.info("Pcap device determined");

        try {
            logger.debug("nif: " + pnif.getName());
            handle = pnif.openLive(65536, PromiscuousMode.PROMISCUOUS, 3600); //snaplength, mode, timeout

        }catch(PcapNativeException e){
            logger.error("Failed to open Handler");
            e.printStackTrace();
        }

        logger.info("Handler created");
        logger.info("Sniffer Initialized");
    }

    @Nullable
    public Packet sniff(Class packetType){
        try {
            currentPacket = handle.getNextPacket();
        }catch(NotOpenException e){
            logger.error("Sniffer must be initialized before capturing!");
            logger.error(e.getMessage());
        }

        if(currentPacket==null) return null;

        if(currentPacket.get(packetType)!=null){
            return currentPacket.get(packetType);
        }else{
            return sniff(packetType);
        }
    }

    @Nullable
    public Packet sniff(){
        try {
            currentPacket = handle.getNextPacket();
        }catch(NotOpenException e){
            logger.error("Sniffer must be initialized before capturing!");
            logger.error(e.getMessage());
        }
        return currentPacket;

    }

}
