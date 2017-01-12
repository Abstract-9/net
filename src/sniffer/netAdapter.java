package sniffer;

import com.sun.istack.internal.Nullable;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class netAdapter {

    private static Logger logger = LoggerFactory.getLogger(netAdapter.class);
    private ArrayList<netInterface> interfaces = new ArrayList<>();

    public netAdapter(){
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
            if(!pnif.isLoopBack()) {
                for (NetworkInterface nif : nifs) {
                    for (InetAddress addr : Collections.list(nif.getInetAddresses())) {
                        for (PcapAddress pcapaddr : pnif.getAddresses()) {
                            InetAddress paddr = pcapaddr.getAddress();
                            if(paddr.equals(addr)){
                                interfaces.add(new netInterface(pnif, nif));
                            }
                        }
                    }
                }
            }
        }
    }

    @Nullable
    public ArrayList<String> getInterfaceNames(){
        ArrayList<String> tmp = new ArrayList<>();
        for(netInterface nif : interfaces){
            tmp.add(nif.getName());
        }
        return tmp;
    }

    public ArrayList<String> getInterfaceDisplayNames(){
        ArrayList<String> tmp = new ArrayList<>();
        for(netInterface nif : interfaces){
            tmp.add(nif.getDisplayName());
        }
        return tmp;
    }

    public ArrayList<netInterface> getInterfaces(){
        return interfaces;
    }



}
