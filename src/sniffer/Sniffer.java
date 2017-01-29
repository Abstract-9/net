package sniffer;

import app.netApp;
import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;


import java.io.File;

public class Sniffer extends AbstractSniffer {

    public Sniffer(PcapNetworkInterface pnif, boolean init){
        this.pnif = pnif;
        if(init) init();
    }

    @Override
    public void init(){
        startTime = System.currentTimeMillis();

        logger.info("Initializing Sniffer");

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

    public void close(){
        handle.close();
        logger.info("Sniffer Closed");
    }

}
