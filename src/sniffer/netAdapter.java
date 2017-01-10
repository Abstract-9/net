package sniffer;

import com.sun.istack.internal.Nullable;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

class netAdapter {

    private Logger logger = LoggerFactory.getLogger(netAdapter.class);

    @Nullable
    public List<PcapNetworkInterface> getInterfaces(){
        try {
            return Pcaps.findAllDevs();
        }catch(PcapNativeException e){
            logger.warn("UNABLE TO FIND NETWORK INTERFACES!");
            logger.debug(e.getMessage());
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
