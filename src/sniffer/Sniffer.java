package sniffer;

import app.netApp;
import com.sun.istack.internal.Nullable;
import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


import java.io.File;
import java.net.InetAddress;
import java.net.UnknownHostException;

public class Sniffer {

    private static PcapHandle handle;
    private static Logger logger = LoggerFactory.getLogger(Sniffer.class);
    private static PcapNetworkInterface pnif;
    private static Packet currentPacket;
    private static long startTime;
    private static boolean initialized = false;
    private PcapDumper dumper;


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

        if(handle!=null) logger.info("Handler created");

        try {
            File directory = new File(netApp.directory);
            File file = File.createTempFile("dump", ".pcap", directory);

            this.dumper = handle.dumpOpen(file.getAbsolutePath());

            logger.info("Dumper Initialized to " + file.getAbsolutePath());
        }catch (Exception e){
            logger.error("unable to open pcapDump! Captured packets will be lost!");
            logger.debug("handle " + handle);
            logger.debug(e.getMessage());
        }

        logger.info("Sniffer Initialized on " + pnif.getAddresses().get(1));
        initialized = true;
    }

    @Nullable
    Packet nextPacket(){
        try {
            currentPacket = handle.getNextPacket();
        }catch(NotOpenException e){
            logger.error("Sniffer must be initialized before capturing!");
            logger.error(e.getMessage());
        }catch(IllegalArgumentException e){
            currentPacket = nextPacket();
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

    public PcapNetworkInterface getPnif(){
        return pnif;
    }

    public PcapDumper getDumper(){
        return dumper;
    }

}
