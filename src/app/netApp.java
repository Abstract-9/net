package app;

import javafx.application.Application;

import javafx.collections.ObservableList;

import javafx.fxml.FXMLLoader;

import javafx.scene.Node;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Button;
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

        primaryStage.show();
    }

    public Stage getPrimaryStage(){
        logger.debug("Primary Stage: " + primaryStage.getTitle());
        return primaryStage;
    }

    @Override
    public void stop() throws Exception {
        if(Controller.isSniffing()) ((Button)currentScene.lookup("#toolbarStop")).fire();
        super.stop();
    }

    public static void main(String[] args) {
        launch(args);
    }
}
