package University.Controllers;

import University.Encryption.CipherUtil;
import University.Encryption.DigitalSignatureEmail;
import University.Encryption.RSA;

import com.jfoenix.controls.JFXCheckBox;
import com.jfoenix.controls.JFXPasswordField;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.scene.Node;
import javafx.scene.control.Alert;
import javafx.scene.control.TextFormatter;
import javafx.stage.Stage;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.ResourceBundle;
import java.util.function.UnaryOperator;


import static University.Info.MailInfo.*;
import static University.Utilities.FileUtility.chooseDirectory;

public class EncryptionController implements Initializable {

    @FXML
    private JFXCheckBox sign_email;

    @FXML
    private JFXCheckBox crypt_email;

    @FXML
    private JFXCheckBox generate_folders;

    @FXML
    private JFXCheckBox have_keys_rsa;

    @FXML
    private JFXPasswordField fld_password;

    private String username;
    private String content;
    private String to;

    private static String separator = File.separator;
    private static String keysFolderPath = separator + "UsersInfo" + separator;


    private String pathToSigFile;

    public void init(String username, String content, String to) {
        this.username = username.split("@")[0];
        this.content = content;
        this.to = to;
    }

    @Override
    public void initialize(URL location, ResourceBundle resources) {
        have_keys_rsa.setDisable(true);
        fld_password.setDisable(true);

        sign_email.selectedProperty().addListener((observable, oldValue, newValue) -> {
            have_keys_rsa.setDisable(!newValue);
        });

        crypt_email.selectedProperty().addListener((observable, oldValue, newValue) -> {
            fld_password.setDisable(!newValue);
        });

        UnaryOperator<TextFormatter.Change> filter = change -> change.getControlNewText().matches("[0-9]?\\p{XDigit}{0,16}") ? change : null;

        TextFormatter<Integer> formatter = new TextFormatter<>(null, null, filter);
        fld_password.setTextFormatter(formatter);
    }

    public static void checkUserDir(String username, String to) {


        String userFolderPath = System.getProperty("user.dir") + separator + "UsersInfo" + separator + to;

        globalSignFolder = userFolderPath + separator + "Signs";

        if (!Files.exists(Paths.get(userFolderPath))) {
            File userFolder = new File(userFolderPath);
            userFolder.mkdirs();
        }
        String cipherKeyPath = userFolderPath + separator + "cipherKeys";
        String signKeyPath = userFolderPath + separator + "signKeys";

        if (!Files.exists(Paths.get(cipherKeyPath))) {
            File cipherKeysFolder = new File(cipherKeyPath);
            cipherKeysFolder.mkdirs();
        }
        if (!Files.exists(Paths.get(signKeyPath))) {
            File signKeysFolder = new File(signKeyPath);
            signKeysFolder.mkdirs();
        }
        if (!Files.exists(Paths.get(globalSignFolder))) {
            File signsFolder = new File(globalSignFolder);
            signsFolder.mkdirs();
        }
        String keysPath = DigitalSignatureEmail.generateKeysRSA(signKeyPath, username);
        pathToRSAPublicKey = keysPath + RSA_PUBLIC_KEY_EXT;
        pathToRSAPrivateKey = keysPath + RSA_PRIVATE_KEY_EXT;
        RSA.generateKeysRSA(cipherKeyPath, username);


//        } else {
//            String cipherKeyPath = keysFolderPath + separator + "cipherKeys" + separator + username;
//            String signKeyPath = keysFolderPath + separator + "signKeys" + separator + username;
//            pathToRSAPublicKeyCipher = cipherKeyPath + PUBLIC_KEY_EXT;
//            pathToRSAPrivateKeyCipher = cipherKeyPath + PRIVATE_KEY_EXT;
//
//            pathToRSAPublicKey = signKeyPath + RSA_PUBLIC_KEY_EXT;
//            pathToRSAPrivateKey = signKeyPath + RSA_PRIVATE_KEY_EXT;
//        }
    }

    public void Send(ActionEvent event) throws NoSuchAlgorithmException, IOException, SignatureException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException {
        if (generate_folders.isSelected()) {
            checkUserDir(username, to);
            pathToSigFile = DigitalSignatureEmail.signEmailWithSaveSign(event, content, username, true);

        } else if (sign_email.isSelected()) {
            if (have_keys_rsa.isSelected()) {
                pathToRSAPublicKey = DigitalSignatureEmail.generateKeysRSA(chooseDirectory(event, "Выберите директорию для ключей RSA").getAbsolutePath(), username);
            }
            pathToSigFile = DigitalSignatureEmail.signEmailWithSaveSign(event, content, username, false);
        }
        if (crypt_email.isSelected()) {
            System.out.println(fld_password.getText());
            if (fld_password.getText().length() == 16) {
                content = CipherUtil.encryptEmail(event, content, fld_password.getText());
            } else {
                new Alert(Alert.AlertType.ERROR, "Пароль должен содержать 16 симоволов от 0 до 9 и от A до F").showAndWait();
            }
        }
        closeWindow(event);
    }

    private void closeWindow(ActionEvent event) {
        Stage stage = (Stage) ((Node) event.getSource()).getScene().getWindow();
        stage.close();
    }

    public String getContent() {
        return content;
    }

    public String getPathToRSAPublicKey() {
        return pathToRSAPublicKey;
    }

    public String getPathToSigFile() {
        return pathToSigFile;
    }
}
