package app;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;

import javafx.scene.control.Alert;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;

import javafx.scene.control.cell.PropertyValueFactory;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;

import org.pcap4j.packet.UnknownPacket;
import sniffer.CaptureLoop;
import sniffer.Sniffer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PacketCellFactory{

    private static Sniffer sniffer;
    private static TableView packetTable;
    private Logger logger = LoggerFactory.getLogger(this.getClass());
    private ObservableList<PacketCell> packetCells = FXCollections.observableArrayList();
    private int counter = 1;
    private CaptureLoop captureLoop;
    private Alert bindingAlert = new Alert(Alert.AlertType.INFORMATION);

    PacketCellFactory(Sniffer sniffer, TableView packetTable){
        this.sniffer = sniffer;
        this.packetTable = packetTable;
    }

    public void start(){
        sniffer.init();
        formatTable();
        CaptureLoop loop = new CaptureLoop(sniffer, this);
        loop.start();
        bindingAlert();
    }

    public void createCell(Packet packet){
        String src = "", dest = "";
        if(packet!=null) {

            while (packet.getPayload() != null) {
                if (packet.getClass().equals(IpV4Packet.class)) {
                    src = ((IpV4Packet.IpV4Header) packet.getHeader()).getSrcAddr().toString();
                    dest = ((IpV4Packet.IpV4Header) packet.getHeader()).getDstAddr().toString();
                }
                if (packet.getPayload().getClass() != UnknownPacket.class) packet = packet.getPayload();
                else break;
            }

            try{
                packetCells.add(new PacketCell(
                        counter++,
                        sniffer.getHandle().getTimestamp().getTime() - sniffer.getStartTime(),
                        src,
                        dest,
                        packet.getClass().getName().substring(18).replace("Packet", ""),
                        packet.getRawData().length,
                        buildInfo(packet)
                ));
            }catch (NullPointerException e){}

        }
    }



    public void stop(){
        captureLoop.stop();
        sniffer.close();
    }

    private void formatTable(){
        ObservableList<TableColumn> columns = packetTable.getColumns();
        columns.get(0).setCellValueFactory(new PropertyValueFactory<PacketCell, Integer>("num"));
        columns.get(1).setCellValueFactory(new PropertyValueFactory<PacketCell, Double>("time"));
        columns.get(2).setCellValueFactory(new PropertyValueFactory<PacketCell, String>("src"));
        columns.get(3).setCellValueFactory(new PropertyValueFactory<PacketCell, String>("dest"));
        columns.get(4).setCellValueFactory(new PropertyValueFactory<PacketCell, String>("proto"));
        columns.get(5).setCellValueFactory(new PropertyValueFactory<PacketCell, Integer>("length"));
        columns.get(6).setCellValueFactory(new PropertyValueFactory<PacketCell, String>("info"));
        packetTable.setItems(packetCells);
    }

    private String buildInfo(Packet packet){

        return packet.getClass().getName().substring(18).replace("Packet", "");

    }
    private void bindingAlert(){
        bindingAlert.setTitle("Binding");
        bindingAlert.setHeaderText("Please Wait");
        bindingAlert.setContentText("Network Interface Binding In Progress");
        bindingAlert.show();
    }
}
