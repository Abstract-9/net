package app;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;

import javafx.fxml.FXML;

import javafx.scene.control.*;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.layout.GridPane;

import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import sniffer.Sniffer;
import sniffer.netAdapter;
import sniffer.netInterface;

public class Controller extends GridPane{

    private Logger logger = LoggerFactory.getLogger(Controller.class);

    @FXML private Button toolbarStart, startButton;
    @FXML private ListView intList;
    @FXML private TableView packetTable;
    @FXML private TabPane tabs;

    private netAdapter adapter = new netAdapter();
    private static boolean sniffing = false;

    public void initialize(){

        ObservableList<String> nifs = FXCollections.observableArrayList();
        nifs.addAll(adapter.getInterfaceDisplayNames());
        intList.setItems(nifs);

        startButton.setGraphic(new ImageView(new Image(getClass().getResourceAsStream("resource/start_button_small.png"))));
        toolbarStart.setGraphic(new ImageView(new Image(getClass().getResourceAsStream("resource/start_button_xs.png"))));

    }

    @FXML
    public void startSniffer(){
        ObservableList<String> selectedSniffers =
                intList.getSelectionModel().getSelectedItems();
        if(selectedSniffers.size()>1){
            Dialog<Void> dialog = new Dialog<>();
            dialog.setContentText("Please select only 1 network interface");
            dialog.show();
        }else{
            String interfaceName = selectedSniffers.get(0);
            netInterface nif = adapter.getInterfaceByDisplayName(interfaceName);
            Sniffer sniffer = null;
            try {
                sniffer = new Sniffer(Pcaps.getDevByAddress(nif.getAddresses().get(0)), false);
            }catch (PcapNativeException e){
                logger.error("Invalid interface used");
                logger.debug(e.getMessage());
                Dialog<Void> dialog = new Dialog<>();
                dialog.setContentText("Unable to capture from this interface. Please select another.");
                dialog.show();
            }
            PacketCellFactory.start();
        }


    }

    static boolean isSniffing(){
        return sniffing;
    }
}
