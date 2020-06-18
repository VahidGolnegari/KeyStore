package com.golnegari.keystoreexample.encryption

import android.content.Context
import android.os.Build
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import javax.crypto.Cipher
import javax.crypto.SecretKey

class EncryptionService(context: Context){

    private var keyStoreWrapper = KeyStoreWrapper(context)
    private var encryptedSymmetricKey : String? = null
    private var isMareshmallow = (Build.VERSION.SDK_INT >= 23)
    private var cryptMode = -1;

    companion object {
        val MASTER_KEY = "MASTER_KEY"
        val SHORT_MODE = 1
        val LONG_MODE = 2
    }

    fun createMasterKey(keyPassword: String? = null , mode : Int = SHORT_MODE) {
        cryptMode = mode
        if (cryptMode == SHORT_MODE) {
            keyStoreWrapper.createAndroidKeyStoreAsymmetricKey(MASTER_KEY)
        } else if (cryptMode == LONG_MODE) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                createAndroid_SymmetricKey()
            } else {
                createDefault_SymmetricKey()
            }
        }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun createAndroid_SymmetricKey() {
        keyStoreWrapper.createAndroidKeyStoreSymmetricKey(MASTER_KEY)
    }

    private fun createDefault_SymmetricKey() {
        val symmetricKey = keyStoreWrapper.createDefaultSymmetricKey()
        val masterKey = keyStoreWrapper.createAndroidKeyStoreAsymmetricKey(MASTER_KEY)
        encryptedSymmetricKey = CipherWrapper(CipherWrapper.TRANSFORMATION_ASYMMETRIC).wrapKey(symmetricKey, masterKey.public)
    }


    fun encrypt(data: String, keyPassword: String? = null): String {
        if (cryptMode == SHORT_MODE) {
            val masterKey = keyStoreWrapper.getAndroidKeyStore_AsymmetricKeyPair(MASTER_KEY)
            return CipherWrapper(CipherWrapper.TRANSFORMATION_ASYMMETRIC).encrypt(data, masterKey?.public)
        } else {
            return if (isMareshmallow) {
                encryptWithAndroidSymmetricKey(data)
            } else {
                encryptWithDefaultSymmetricKey(data)
            }
        }
    }

    fun decrypt(data: String, keyPassword: String? = null): String {
        if (cryptMode == SHORT_MODE) {
            val masterKey = keyStoreWrapper.getAndroidKeyStore_AsymmetricKeyPair(MASTER_KEY)
            return CipherWrapper(CipherWrapper.TRANSFORMATION_ASYMMETRIC).decrypt(data, masterKey?.private)
        } else {
            return if (isMareshmallow) {
                decryptWithAndroidSymmetricKey(data)
            } else {
                decryptWithDefaultSymmetricKey(data)
            }
        }
    }


    private fun encryptWithAndroidSymmetricKey(data: String): String {
        val masterKey = keyStoreWrapper.getAndroidKeyStoreSymmetricKey(MASTER_KEY)
        return CipherWrapper(CipherWrapper.TRANSFORMATION_SYMMETRIC).encrypt(data, masterKey , true)
    }

    private fun decryptWithAndroidSymmetricKey(data: String): String {
        val masterKey = keyStoreWrapper.getAndroidKeyStoreSymmetricKey(MASTER_KEY)
        return CipherWrapper(CipherWrapper.TRANSFORMATION_SYMMETRIC).decrypt(data, masterKey , true)
    }

    private fun encryptWithDefaultSymmetricKey(data: String): String {
        val masterKey = keyStoreWrapper.getAndroidKeyStore_AsymmetricKeyPair(MASTER_KEY)
        val symmetricKey = CipherWrapper(CipherWrapper.TRANSFORMATION_ASYMMETRIC).unWrapKey(encryptedSymmetricKey!!, KeyProperties.KEY_ALGORITHM_AES, Cipher.SECRET_KEY, masterKey?.private) as SecretKey
        return CipherWrapper(CipherWrapper.TRANSFORMATION_SYMMETRIC).encrypt(data, symmetricKey , true)
    }

    private fun decryptWithDefaultSymmetricKey(data: String): String {
        val masterKey = keyStoreWrapper.getAndroidKeyStore_AsymmetricKeyPair(MASTER_KEY)
        val symmetricKey = CipherWrapper(CipherWrapper.TRANSFORMATION_ASYMMETRIC).unWrapKey(encryptedSymmetricKey!!, KeyProperties.KEY_ALGORITHM_AES, Cipher.SECRET_KEY, masterKey?.private) as SecretKey
        return CipherWrapper(CipherWrapper.TRANSFORMATION_SYMMETRIC).decrypt(data, symmetricKey , true)
    }


}