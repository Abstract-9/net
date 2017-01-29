package sniffer;

import javafx.scene.control.Alert;
import org.pcap4j.core.*;

import java.io.File;

public class OfflineSniffer extends AbstractSniffer{

    public OfflineSniffer(File pcapFile, boolean init){
        this.pcapFile = pcapFile;
        if(init) init();
    }

    @Override
    public void init() {
        startTime = System.currentTimeMillis();

        logger.info("Initializing Offline Sniffer");

        try{
            logger.info("File: " + pcapFile.getAbsolutePath());
            handle = Pcaps.openOffline(pcapFile.getAbsolutePath());
        }catch (PcapNativeException e){
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle("Error");
            alert.setHeaderText("Invalid File");
            alert.setContentText("Unable to read capture data from " + pcapFile.getAbsolutePath() +
                    ". Please make sure this data was captured using Net.");
            alert.show();
        }

        logger.info("Offline Sniffer initialized to " + pcapFile.getAbsolutePath());
        initialized = true;
    }

    @Override
    public void close() {
        handle.close();
        logger.info("Offline Sniffer Closed");

    }
}
