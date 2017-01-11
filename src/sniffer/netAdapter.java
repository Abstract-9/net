package sniffer;

import com.sun.istack.internal.Nullable;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class netAdapter {

    private static Logger logger = LoggerFactory.getLogger(netAdapter.class);

    @Nullable
    public static List<PcapNetworkInterface> getInterfaces(){
        ArrayList<NetworkInterface> nifs = null;
        ArrayList<PcapNetworkInterface> pnifs = null;
        try {
            nifs = Collections.list(NetworkInterface.getNetworkInterfaces());
            pnifs = (ArrayList<PcapNetworkInterface>) Pcaps.findAllDevs();
        }catch (SocketException e){
            logger.warn("UNABLE TO FIND SOCKET NETWORK INTERFACES!");
            logger.debug(e.getMessage());
        }catch (PcapNativeException e){
            logger.warn("UNABLE TO FIND PCAP NETWORK INTERFACES!");
            logger.debug(e.getMessage());
        }
        for(PcapNetworkInterface pnif : pnifs){
            for (NetworkInterface nif : nifs){
            }
        }
        try {
            return Pcaps.findAllDevs();
        }catch(PcapNativeException e){

        }
        return null;
    }

    @Nullable
    public PcapNetworkInterface getInterface(String name){
        try {
            return Pcaps.getDevByName(name);
        }catch(PcapNativeException e){
            logger.error("PASSED INTERFACE DOES NOT EXIST");
            logger.debug(e.getMessage());
        }
        return null;
    }
}
