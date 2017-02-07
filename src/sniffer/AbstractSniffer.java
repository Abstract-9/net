package sniffer;


import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

public abstract class AbstractSniffer {


    static PcapHandle handle;
    static Logger logger = LoggerFactory.getLogger(Sniffer.class);
    static File pcapFile;
    static PcapNetworkInterface pnif;
    private static Packet currentPacket;
    static long startTime;
    static boolean initialized = false;
    PcapDumper dumper;

    public abstract void init();
    public abstract void close();

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
    boolean isInitialized(){
        return initialized;
    }
    public PcapNetworkInterface getPnif(){
        return pnif;
    }
    public PcapDumper getDumper(){
        return dumper;
    }
    public File getPcapFile() { return pcapFile; }
}
