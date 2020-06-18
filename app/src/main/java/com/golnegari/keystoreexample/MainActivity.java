package com.golnegari.keystoreexample;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;

import android.content.Intent;
import android.os.Bundle;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.view.View;
import android.widget.Button;

public class MainActivity extends AppCompatActivity{

    private Button btnKeyChain;
    private Button btnKeyStore;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        btnKeyChain = findViewById(R.id.button_mainactivity_keychain);
        btnKeyStore = findViewById(R.id.button_mainactivity_keystore);
        btnKeyStore.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                startActivity(new Intent(MainActivity.this , KeyStoreActivity.class));
            }
        });
    }

    public void onKeyChainClicked(){
        Intent intent = KeyChain.createInstallIntent();
    }

}
