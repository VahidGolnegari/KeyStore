package com.golnegari.keystoreexample;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import com.golnegari.keystoreexample.encryption.EncryptionService;

public class KeyStoreActivity extends AppCompatActivity {

    private Button btnEncrypt , btnDecrypt;
    private Button btnRemoveAllKeys;
    private TextView message , decryptMessage;

    private final String messageValue = "Hello World";
    private String encryptedMessage;
    private String decryptedMessage;

    private EncryptionService encryptionService;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_keystore);
        encryptionService = new EncryptionService(this);
        encryptionService.createMasterKey(null , EncryptionService.Companion.getLONG_MODE());
        btnDecrypt = findViewById(R.id.button_keystore_decrypt);
        btnEncrypt = findViewById(R.id.button_keystore_encrypt);
        message = findViewById(R.id.textview_keystore_message);
        btnRemoveAllKeys = findViewById(R.id.button_keystore_removekey);
        decryptMessage = findViewById(R.id.textview_keystore_decryptedmessage);
        btnEncrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                encryptedMessage = encryptionService.encrypt(messageValue  , null);
                message.setText(encryptedMessage);
            }
        });

        btnDecrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                decryptedMessage = encryptionService.decrypt(encryptedMessage , null);
                decryptMessage.setText(decryptedMessage);
            }
        });
    }
}
