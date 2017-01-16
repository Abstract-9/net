package app;


import javafx.scene.control.TableView;
import sniffer.Sniffer;



public class PacketCellFactory {

    static Sniffer sniffer;
    static TableView packetTable;

    PacketCellFactory(Sniffer sniffer, TableView packetTable){
        this.sniffer = sniffer;
        this.packetTable = packetTable;
    }

    public void start(Sniffer sniffer, TableView packetTable){
        this.sniffer = sniffer;
        this.packetTable = packetTable;

    }

    public static void start(){
        sniffer.init();
        while(Controller.isSniffing()){
        }

    }

    public static void stop(){

    }


}
