package app;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;

import javafx.fxml.FXML;

import javafx.scene.control.Button;
import javafx.scene.control.ListView;
import javafx.scene.control.TableView;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.layout.GridPane;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import sniffer.Sniffer;
import sniffer.netAdapter;

public class Controller extends GridPane{

    private Logger logger = LoggerFactory.getLogger(Controller.class);

    @FXML private Button toolbarStart, startButton;
    @FXML private ListView intList;
    @FXML private TableView packetTable;

    private netAdapter adapter = new netAdapter();

    public void initialize(){

        ObservableList<String> nifs = FXCollections.observableArrayList();
        nifs.addAll(adapter.getInterfaceDisplayNames());
        intList.setItems(nifs);

        startButton.setGraphic(new ImageView(new Image(getClass().getResourceAsStream("resource/start_button_small.png"))));
        toolbarStart.setGraphic(new ImageView(new Image(getClass().getResourceAsStream("resource/start_button_xs.png"))));

    }

    @FXML
    public void startSniffer(){


    }
}
