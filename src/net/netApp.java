package net;

import javafx.application.Application;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.fxml.FXMLLoader;
import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.ListView;
import javafx.stage.Stage;
import org.pcap4j.core.PcapNetworkInterface;
import sniffer.netAdapter;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;

public class netApp extends Application {

    ArrayList<PcapNetworkInterface> nifList = new ArrayList<>();
    Parent root;
    ObservableList<Node> nodes;
    netAdapter adapter = new netAdapter();

    @Override
    public void start(Stage primaryStage) throws Exception{
        root = FXMLLoader.load(getClass().getResource("net.fxml"));

        primaryStage.setTitle("Net");
        primaryStage.setScene(new Scene(root));
        primaryStage.show();

        nodes = root.getChildrenUnmodifiable();
        ListView nifList = null;
        for(Node n : nodes){
            if(n.getId()!=null && n.getId().equals("intList")){
                nifList = (ListView) n;
                break;
            }
        }
        ObservableList<String> nifs = FXCollections.observableArrayList();
        nifs.addAll(adapter.getInterfaceDisplayNames());
        nifList.setItems(nifs);
    }


    public static void main(String[] args) {
        launch(args);
    }
}
