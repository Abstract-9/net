package net;

import javafx.application.Application;

import javafx.collections.ObservableList;

import javafx.fxml.FXMLLoader;

import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class netApp extends Application {

    private Parent root;
    private Scene currentScene;
    private ObservableList<Node> nodes;
    private Stage primaryStage;
    private Logger logger = LoggerFactory.getLogger(netApp.class);

    @Override
    public void init() throws Exception{

        root = FXMLLoader.load(getClass().getResource("layout/net.fxml"));

    }

    @Override
    public void start(Stage primaryStage) throws Exception{

        currentScene = new Scene(root);
        this.primaryStage = primaryStage;

        primaryStage.setTitle("Net");
        primaryStage.setScene(currentScene);

        load();

        primaryStage.show();


    }

    private void load() {



    }





    public static void main(String[] args) {
        launch(args);
    }
}
