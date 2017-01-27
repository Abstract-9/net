package app;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;

import javafx.scene.control.*;

import javafx.scene.control.cell.PropertyValueFactory;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapDumper;
import org.pcap4j.packet.*;

import sniffer.CaptureLoop;
import sniffer.Sniffer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;

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
            Packet tmpPacket = packet;
            while(tmpPacket.getPayload()!=null){
                tmpPacket=tmpPacket.getPayload();
                if (tmpPacket.getClass().equals(IpV4Packet.class)) {
                    src = ((IpV4Packet.IpV4Header) tmpPacket.getHeader()).getSrcAddr().toString();
                    dest = ((IpV4Packet.IpV4Header) tmpPacket.getHeader()).getDstAddr().toString();
                }
                if(tmpPacket.getClass() != UnknownPacket.class) protocol = tmpPacket.getClass().getName().substring(18).replace("Packet", "");
                else {
                    String tmp = packetInfoBuilder.resolveProtocol(tmpPacket);
                    if(!tmp.equals("Unknown")) protocol=tmp;
                    break;
                }
            }

            if(src.equals("")){
                if(packet.get(ArpPacket.class)!=null) {
                    src = packet.get(ArpPacket.class).getHeader().getSrcHardwareAddr().toString();
                    dest = packet.get(ArpPacket.class).getHeader().getDstHardwareAddr().toString();
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
                        packetInfoBuilder.buildInfo(packet.getPayload().getPayload(), protocol)
                ));

                sniffer.getDumper().dump(packets.get(packets.size() - 1), sniffer.getHandle().getTimestamp());
            } catch(NotOpenException e){
                logger.warn("dumping to empty dumper!");
                logger.debug(e.getMessage());
            } catch(Exception e) {
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
            row.setMaxHeight(row.getHeight());

            return row;
        });

        packetTable.getVisibleLeafColumn(4).setCellFactory(column -> {
            return new TableCell<PacketCell, String>() {
                @Override
                protected void updateItem(String item, boolean empty) {
                    super.updateItem(item, empty);

                    setText(empty ? "" : item);

                    getTableRow().getStyleClass().setAll(item, "table-row");
                }
            };
        });


    }



    Packet getPacket(int index) {
        return packets.get(index);
    }

    static Sniffer getSniffer() {
        return sniffer;
    }


}













