package com.golnegari.keystoreexample;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.text.TextUtils;
import android.util.Base64;
import android.view.View;
import android.widget.TextView;

import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

public class WrapKeyApproach extends AppCompatActivity {

    private static final String AndroidKeyStore = "AndroidKeyStore";

    private final String AES_MODE = "AES/GCM/NoPadding";
    private final String RSA_MODE =  "RSA/ECB/PKCS1Padding";

    private static final String ENCRYPTED_KEY = "AES_KEY";
    private static final String SHARED_PREFENCE_NAME = "SecureKeyStore";

    private final String RSA_KEY_ALIAS = "RSA_KEY";
    private final String AES_KEY_ALIAS = "AES_KEY";

    private byte[] FIXED_IV ;

    private String originalMessage = "Hello World";
    private String encryptedMessage;
    private String decryptedMessage;

    private TextView txtEncryptedMessage;
    private TextView txtDecrptedMessage;


    private KeyStore keyStore;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_keystore);
        try {
            keyStore = KeyStore.getInstance(AndroidKeyStore);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        try {
            keyStore.load(null);
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            createKey23Api();
        } else {
            createKeyPairKey(this);
        }

    }

    public void onEncryptClicked(View view) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
               encryptedMessage =  encrypt(originalMessage , this);
            } catch (Exception e) {
                e.printStackTrace();
            }

        } else {
            try {
                encryptedMessage = defaultDecrypt(this , originalMessage);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        if (!TextUtils.isEmpty(encryptedMessage)) {
            txtEncryptedMessage.setText(encryptedMessage);
        }
    }

    public void onDecryptedClicked(View view) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            try {
                decryptedMessage =  encrypt(encryptedMessage , this);
            } catch (Exception e) {
                e.printStackTrace();
            }

        } else {
            try {
                decryptedMessage = defaultDecrypt(this , encryptedMessage);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        if (!TextUtils.isEmpty(decryptedMessage)) {
            txtDecrptedMessage.setText(decryptedMessage);
        }
    }



    @RequiresApi(api = Build.VERSION_CODES.M)
    private void createKey23Api(){
        try {
            if (!keyStore.containsAlias(AES_KEY_ALIAS)) {
                KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, AndroidKeyStore);
                keyGenerator.init(
                        new KeyGenParameterSpec.Builder(AES_KEY_ALIAS,
                                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                                .setRandomizedEncryptionRequired(false)
                                .build());
                keyGenerator.generateKey();
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

    }

    private void createKeyPairKey(Context context){
        // Generate the RSA key pairs
        try {
            if (!keyStore.containsAlias(RSA_KEY_ALIAS)) {
                // Generate a key pair for encryption
                Calendar start = Calendar.getInstance();
                Calendar end = Calendar.getInstance();
                end.add(Calendar.YEAR, 30);
                KeyPairGeneratorSpec spec = new      KeyPairGeneratorSpec.Builder(context)
                        .setAlias(RSA_KEY_ALIAS)
                        .setSubject(new X500Principal("CN=" + RSA_KEY_ALIAS))
                        .setSerialNumber(BigInteger.TEN)
                        .setStartDate(start.getTime())
                        .setEndDate(end.getTime())
                        .build();
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", AndroidKeyStore);
                kpg.initialize(spec);
                kpg.generateKeyPair();
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
    }



    private java.security.Key getSecretKey(Context context) throws Exception {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            return keyStore.getKey(AES_KEY_ALIAS, null);
        } else {
            SharedPreferences pref = context.getSharedPreferences(SHARED_PREFENCE_NAME, Context.MODE_PRIVATE);
            String enryptedKeyB64 = pref.getString(ENCRYPTED_KEY, null);
            if (enryptedKeyB64 == null) {
                byte[] key = new byte[16];
                SecureRandom secureRandom = new SecureRandom();
                secureRandom.nextBytes(key);
                byte[] encryptedKey = new byte[0];
                try {
                    encryptedKey = rsaEncrypt(key);
                    enryptedKeyB64 = Base64.encodeToString(encryptedKey, Base64.DEFAULT);
                    SharedPreferences.Editor edit = pref.edit();
                    edit.putString(ENCRYPTED_KEY, enryptedKeyB64);
                    edit.apply();
                } catch (Exception e) {
                    e.printStackTrace();
                }

            }
            // need to check null, omitted here
            byte[] encryptedKey = Base64.decode(enryptedKeyB64, Base64.DEFAULT);
            byte[] key = rsaDecrypt(encryptedKey);
            return new SecretKeySpec(key, "AES");
        }
    }


    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    private String encrypt(String data , Context context) throws Exception {
        Cipher c = Cipher.getInstance(AES_MODE);
        if (FIXED_IV.length == 0 ) {
            FIXED_IV = c.getIV();
        }
        c.init(Cipher.ENCRYPT_MODE, getSecretKey(context), new GCMParameterSpec(128, FIXED_IV));
        byte[] encodedBytes = c.doFinal(data.getBytes());
        return Base64.encodeToString(encodedBytes, Base64.DEFAULT);
    }

    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    private String decrypt(String data , Context context) throws Exception {
        Cipher c = Cipher.getInstance(AES_MODE);
        c.init(Cipher.DECRYPT_MODE, getSecretKey(context), new GCMParameterSpec(128, FIXED_IV));
        byte[] decodedBytes = c.doFinal(data.getBytes());
        return new String(decodedBytes);
    }


    private byte[] rsaEncrypt(byte[] secret) throws Exception{
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(RSA_KEY_ALIAS, null);
        // Encrypt the text
        Cipher inputCipher = Cipher.getInstance(RSA_MODE, "AndroidOpenSSL");
        inputCipher.init(Cipher.ENCRYPT_MODE, privateKeyEntry.getCertificate().getPublicKey());

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, inputCipher);
        cipherOutputStream.write(secret);
        cipherOutputStream.close();

        return outputStream.toByteArray();
    }

    private  byte[] rsaDecrypt(byte[] encrypted) throws Exception {
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)keyStore.getEntry(RSA_KEY_ALIAS, null);
        Cipher output = Cipher.getInstance(RSA_MODE, "AndroidOpenSSL");
        output.init(Cipher.DECRYPT_MODE, privateKeyEntry.getPrivateKey());
        CipherInputStream cipherInputStream = new CipherInputStream(new ByteArrayInputStream(encrypted), output);
        ArrayList<Byte> values = new ArrayList<>();
        int nextByte;
        while ((nextByte = cipherInputStream.read()) != -1) {
            values.add((byte)nextByte);
        }

        byte[] bytes = new byte[values.size()];
        for(int i = 0; i < bytes.length; i++) {
            bytes[i] = values.get(i);
        }
        return bytes;
    }

    public String defaultEncrypt(Context context, String input) throws Exception {
        Cipher c = Cipher.getInstance(AES_MODE);
        c.init(Cipher.ENCRYPT_MODE, getSecretKey(context));
        byte[] encodedBytes = c.doFinal(input.getBytes());
        return Base64.encodeToString(encodedBytes, Base64.DEFAULT);
    }


    public String defaultDecrypt(Context context, String input) throws Exception {
        Cipher c = Cipher.getInstance(AES_MODE);
        c.init(Cipher.DECRYPT_MODE, getSecretKey(context));
        byte[] decodedBytes = c.doFinal(Base64.decode(input , Base64.DEFAULT));
        return new String(decodedBytes);
    }




}
