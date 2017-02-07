package app;

import javafx.scene.control.Alert;
import javafx.scene.control.ButtonBar;
import javafx.scene.control.ButtonType;

import java.io.File;
import java.util.Optional;

import static app.Dialogs.button.*;


public class Dialogs {

    public enum button{
        Yes (new ButtonType("Yes")),
        No (new ButtonType("No")),
        Cancel(new ButtonType("Cancel", ButtonBar.ButtonData.CANCEL_CLOSE)),
        Ok (new ButtonType("Ok")),
        Retry (new ButtonType("Retry"));

        private ButtonType bType;

        button(ButtonType b){
            bType = b;
        }

        public ButtonType getButtonType() {
            return bType;
        }
    }

    static Optional<ButtonType> showUnsavedCloseFile(){
        Alert save = new Alert(Alert.AlertType.CONFIRMATION);
        save.setHeaderText("Do you want to save the captured data before starting a new capture?");
        save.setContentText("All collected data will be lost if you dont save it.");
        save.getButtonTypes().setAll(Yes.getButtonType(), No.getButtonType(), Cancel.getButtonType());
        return save.showAndWait();

    }

    static void showUnableToSave(File file){
        Alert error = new Alert(Alert.AlertType.ERROR);
        error.setTitle("Error!");
        error.setHeaderText("Unable to save file!");
        error.setContentText("Unable to save captured data to " + file.getAbsolutePath());
        error.getButtonTypes().setAll(Ok.getButtonType(), Retry.getButtonType());
        while(error.showAndWait().isPresent() && error.showAndWait().get().equals(Retry.getButtonType())){
            Controller.saveFile();
        }

    }
}
