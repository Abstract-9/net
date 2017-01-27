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

import java.nio.file.Path;


public class netApp extends Application {

    private Parent root;
    private static Scene currentScene;
    private ObservableList<Node> nodes;
    private static Stage primaryStage;
    private static Logger logger = LoggerFactory.getLogger(netApp.class);
    public static String directory = netApp.class.getProtectionDomain().getCodeSource().getLocation().getPath().substring(1);

    @Override
    public void init() throws Exception{

        root = FXMLLoader.load(getClass().getResource("layout/net.fxml"));

    }

    @Override
    public void start(Stage primaryStage) throws Exception{

        currentScene = new Scene(root);
        netApp.primaryStage = primaryStage;

        primaryStage.setTitle("Net");
        primaryStage.setScene(currentScene);

        primaryStage.show();
    }

    static Stage getPrimaryStage(){
        logger.debug("Primary Stage: " + primaryStage.getTitle());
        return primaryStage;
    }

    static Scene getCurrentScene(){
        return currentScene;
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
