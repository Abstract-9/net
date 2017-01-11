package sniffer;

import com.sun.istack.internal.Nullable;
import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.*;
import org.pcap4j.packet.Packet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import java.net.InetAddress;
import java.net.UnknownHostException;

public class rawSniffer {

    private static InetAddress local;
    private static PcapHandle handle;
    private static Logger logger = LoggerFactory.getLogger(rawSniffer.class);
    static Packet currentPacket;

    public rawSniffer(boolean init){
        if(init) init();
    }

    public void init(){

        PcapNetworkInterface nif = null;

        logger.info("Initializing Sniffer");

        try {
            local = InetAddress.getLocalHost();
            logger.info("Local Address: " + local);
            nif = Pcaps.getDevByAddress(local);

        }catch(UnknownHostException e){
            logger.error("unable to connect localhost");
            e.printStackTrace();

        }catch(PcapNativeException e){
            logger.error("unable to connect pcap device");
            e.printStackTrace();
        }

        logger.info("Pcap device determined");

        try {
            logger.debug("nif: " + nif.getName());
            handle = nif.openLive(65536, PromiscuousMode.PROMISCUOUS, 3600); //snaplength, mode, timeout

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
