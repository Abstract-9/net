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

    private static PcapHandle handle;
    private static Logger logger = LoggerFactory.getLogger(Sniffer.class);
    private static PcapNetworkInterface pnif;
    private static Packet currentPacket;
    private static long startTime;
    private static boolean initialized = false;


    public Sniffer(PcapNetworkInterface pnif, boolean init){
        this.pnif = pnif;
        if(init) init();
    }


    public void init(){
        startTime = System.currentTimeMillis();

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
        logger.info("Sniffer Initialized on " + pnif.getAddresses().get(1));
        initialized = true;
    }

    @Nullable
    public Packet nextPacket(Class packetType){
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
            return nextPacket(packetType);
        }
    }

    @Nullable
    Packet nextPacket(){
        try {
            currentPacket = handle.getNextPacket();
        }catch(NotOpenException e){
            logger.error("Sniffer must be initialized before capturing!");
            logger.error(e.getMessage());
        }
        return currentPacket;

    }

    public PcapHandle getHandle(){
        return handle;
    }

    public long getStartTime(){
        return startTime;
    }

    public void close(){
        handle.close();
        logger.info("Sniffer Closed");
    }

    boolean isInitialized(){
        return initialized;
    }

}
