package com.golnegari.keystoreexample.encryption

import android.annotation.TargetApi
import android.content.Context
import android.os.Build
import android.security.KeyPairGeneratorSpec
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.util.*
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.security.auth.x500.X500Principal

class KeyStoreWrapper(private val context : Context) {

    private val androidKeyStore : KeyStore = createAndroidKeyStore();

    fun getAndroidKeyStoreSymmetricKey(alias: String): SecretKey? = androidKeyStore.getKey(alias, null) as SecretKey?

    private fun createAndroidKeyStore() : KeyStore {
        val keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        return keyStore;
    }

    fun createAndroidKeyStoreAsymmetricKey(alias : String) : KeyPair {
        val generator = KeyPairGenerator.getInstance("RSA" , "AndroidKeyStore");
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            initGeneratorWithKeyGenParameterSpec(generator, alias)
        } else {
            initGeneratorWithKeyPairGeneratorSpec(generator, alias)
        }
        return generator.generateKeyPair();
    }

    @TargetApi(Build.VERSION_CODES.M)
    private fun initGeneratorWithKeyGenParameterSpec(generator : KeyPairGenerator , alias : String) {
        val builder = KeyGenParameterSpec.Builder(alias , KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
        generator.initialize(builder.build())
    }

    private fun initGeneratorWithKeyPairGeneratorSpec(generator: KeyPairGenerator , alias : String){
        val startDate = Calendar.getInstance()
        val endDate = Calendar.getInstance()
        endDate.add(Calendar.YEAR, 20)
        val builder = KeyPairGeneratorSpec.Builder(context)
                .setAlias(alias)
                .setSerialNumber(BigInteger.ONE)
                .setSubject(X500Principal("CN=${alias} CA Certificate"))
                .setStartDate(startDate.time)
                .setEndDate(endDate.time)
        generator.initialize(builder.build())
    }

    fun getAndroidKeyStore_AsymmetricKeyPair(alias: String): KeyPair? {
        val privateKey = androidKeyStore.getKey(alias, null) as PrivateKey?
        val publicKey = androidKeyStore.getCertificate(alias)?.publicKey
        return if (privateKey != null && publicKey != null) {
            KeyPair(publicKey, privateKey)
        } else {
            null
        }
    }

    fun createDefaultSymmetricKey() : SecretKey {
        val keyGenerator = KeyGenerator.getInstance("AES");
        return keyGenerator.generateKey()
    }

    @RequiresApi(Build.VERSION_CODES.M)
    fun createAndroidKeyStoreSymmetricKey(alias: String) : SecretKey {
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES , "AndroidKeyStore");
        val builder = KeyGenParameterSpec.Builder(alias,KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
        keyGenerator.init(builder.build())
        return keyGenerator.generateKey()
    }

    fun removeAndroidKeyStoreKey(alias: String) = androidKeyStore.deleteEntry(alias)


}