package sniffer;


import app.PacketCellFactory;
import org.pcap4j.packet.Packet;

public class CaptureLoop implements Runnable {

    private boolean running = true;
    private Sniffer sniffer;
    private PacketCellFactory factory;

    public CaptureLoop(Sniffer sniffer, PacketCellFactory factory){
        this.sniffer = sniffer;
        this.factory = factory;
    }

    public void start(){

        if(!this.sniffer.isInitialized()) this.sniffer.init();

        Thread t1 = new Thread(this);
        t1.setName("CaptureLoop");
        t1.start();
    }

    @Override
    public void run() {
        while(running){
            Packet packet = sniffer.nextPacket();
            factory.createCell(packet);
        }
    }

    public void stop(){
        running = false;
    }
}
