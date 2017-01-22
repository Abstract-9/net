package app;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;

import javafx.scene.control.TabPane;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableRow;
import javafx.scene.control.TableView;

import javafx.scene.control.cell.PropertyValueFactory;
import org.pcap4j.packet.*;

import org.pcap4j.util.ByteArrays;
import sniffer.CaptureLoop;
import sniffer.Sniffer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;

public class PacketCellFactory {

    private static Sniffer sniffer;
    private static TableView packetTable;
    private Logger logger = LoggerFactory.getLogger(this.getClass());
    private ObservableList<PacketCell> packetCells = FXCollections.observableArrayList();
    private int counter = 1;
    private CaptureLoop captureLoop;
    private ArrayList<Packet> packets = new ArrayList<>();

    PacketCellFactory(Sniffer sniffer, TableView packetTable) {
        PacketCellFactory.sniffer = sniffer;
        PacketCellFactory.packetTable = packetTable;
    }

    public void start() {
        sniffer.init();
        formatTable();
        captureLoop = new CaptureLoop(sniffer, this);
        captureLoop.start();
    }

    public void createCell(Packet packet) {
        String src = "", dest = "";
        if (packet != null) {
            String protocol = null;
            packets.add(packet);
            do{
                packet=packet.getPayload();
                if (packet.getClass().equals(IpV4Packet.class)) {
                    src = ((IpV4Packet.IpV4Header) packet.getHeader()).getSrcAddr().toString();
                    dest = ((IpV4Packet.IpV4Header) packet.getHeader()).getDstAddr().toString();
                }
                if(packet.getClass() != UnknownPacket.class) protocol = packet.getClass().getName().substring(18).replace("Packet", "");
                else {
                    String tmp = packetInfoBuilder.resolveProtocol(packet);
                    if(!tmp.equals("Unknown")) protocol=tmp;
                    break;
                }
            }while(packet.getPayload()!=null);

            if(src.equals("")){
                if(packet.get(ArpPacket.class)!=null) {
                    src = ((ArpPacket.ArpHeader) packet.getHeader()).getSrcHardwareAddr().toString();
                    dest = ((ArpPacket.ArpHeader) packet.getHeader()).getDstHardwareAddr().toString();
                    protocol = "ARP";
                }
            }

            try {
                packetCells.add(new PacketCell(
                        counter++,
                        ((double)sniffer.getHandle().getTimestamp().getTime() - (double)sniffer.getStartTime())/1000,
                        src.substring(1),
                        dest.substring(1),
                        protocol,
                        packets.get(packets.size() - 1).getRawData().length,
                        packetInfoBuilder.buildInfo(packet, protocol)
                ));
            } catch (Exception e) {
                packets.remove(packets.size() - 1);
            }

        }
    }


    public void stop() {
        captureLoop.stop();
        sniffer.close();
    }


    @SuppressWarnings("unchecked")
    private void formatTable() {
        ObservableList<TableColumn> columns = packetTable.getColumns();
        columns.get(0).setCellValueFactory(new PropertyValueFactory<PacketCell, Integer>("num"));
        columns.get(1).setCellValueFactory(new PropertyValueFactory<PacketCell, Double>("time"));
        columns.get(2).setCellValueFactory(new PropertyValueFactory<PacketCell, String>("src"));
        columns.get(3).setCellValueFactory(new PropertyValueFactory<PacketCell, String>("dest"));
        columns.get(4).setCellValueFactory(new PropertyValueFactory<PacketCell, String>("proto"));
        columns.get(5).setCellValueFactory(new PropertyValueFactory<PacketCell, Integer>("length"));
        columns.get(6).setCellValueFactory(new PropertyValueFactory<PacketCell, String>("info"));
        packetTable.setItems(packetCells);

        packetTable.setRowFactory((tv) -> {
            TableRow<PacketCell> row = new TableRow<>();
            row.setOnMouseClicked(event -> {
                if (event.getClickCount() == 2 && !row.isEmpty()) {
                    ((TabPane) netApp.getCurrentScene().lookup("#tabs")).getSelectionModel().select(2);
                }
            });
            return row;
        });
    }



    Packet getPacket(int index) {
        return packets.get(index);
    }

    static Sniffer getSniffer() {
        return sniffer;
    }
}













