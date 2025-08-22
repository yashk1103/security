#include "../include/com_securemessaging_SecureCrypto.h"
#include "../include/secure_crypto_processor.h"
#include <iostream>
#include <string>
#include <memory>

// C++ helper functions (NOT exported to JNI)
namespace {
    std::string jstringToString(JNIEnv* env, jstring jstr) {
        if (!jstr) return "";
        const char* cstr = env->GetStringUTFChars(jstr, nullptr);
        if (!cstr) return "";
        std::string str(cstr);
        env->ReleaseStringUTFChars(jstr, cstr);
        return str;
    }

    jstring stringToJstring(JNIEnv* env, const std::string& str) {
        return env->NewStringUTF(str.c_str());
    }

    jobject createEncryptionResult(JNIEnv* env, const std::string& encryptedData, const std::string& key) {
        jclass resultClass = env->FindClass("com/securemessaging/EncryptionResult");
        if (!resultClass) return nullptr;
        
        // Constructor signature: (String encryptedData, String key, int keyBits)
        jmethodID constructor = env->GetMethodID(resultClass, "<init>", "(Ljava/lang/String;Ljava/lang/String;I)V");
        if (!constructor) return nullptr;
        
        jstring jEncryptedData = stringToJstring(env, encryptedData);
        jstring jKey = stringToJstring(env, key);
        
        // Determine key bits based on key length (hex characters)
        int keyBits = (key.length() == 128) ? 512 : 1488;
        
        return env->NewObject(resultClass, constructor, jEncryptedData, jKey, keyBits);
    }

    jobject createSystemInfo(JNIEnv* env) {
        jclass systemInfoClass = env->FindClass("com/securemessaging/SystemInfo");
        if (!systemInfoClass) return nullptr;
        
        // Constructor signature: (String version, String algorithm, boolean supports512Bit, boolean supports1488Bit, String securityFeatures)
        jmethodID constructor = env->GetMethodID(systemInfoClass, "<init>", "(Ljava/lang/String;Ljava/lang/String;ZZLjava/lang/String;)V");
        if (!constructor) return nullptr;
        
        jstring jVersion = stringToJstring(env, "1.0.0");
        jstring jAlgorithm = stringToJstring(env, "AES-512 Equivalent (Dual AES-256)");
        jboolean supports512 = JNI_TRUE;
        jboolean supports1488 = JNI_TRUE;
        jstring jSecurityFeatures = stringToJstring(env, "Random IV, PKCS7 Padding, Secure Key Generation");
        
        return env->NewObject(systemInfoClass, constructor, jVersion, jAlgorithm, supports512, supports1488, jSecurityFeatures);
    }

    void handleException(JNIEnv* env, const std::exception& e) {
        jclass exceptionClass = env->FindClass("java/lang/RuntimeException");
        if (exceptionClass) {
            env->ThrowNew(exceptionClass, e.what());
        }
    }
}

// JNI exported functions with extern "C" linkage
extern "C" {

JNIEXPORT jstring JNICALL Java_com_securemessaging_SecureCrypto_testConnection
(JNIEnv* env, jobject obj) {
    return env->NewStringUTF("JNI connection working! Core crypto loaded successfully.");
}

JNIEXPORT jobject JNICALL Java_com_securemessaging_SecureCrypto_encryptMessage
(JNIEnv* env, jobject obj, jstring message, jboolean use1488BitKey) {
    try {
        std::string cppMessage = jstringToString(env, message);
        SecureCryptoProcessor crypto;
        
        auto result = crypto.encryptMessage(cppMessage, use1488BitKey == JNI_TRUE);
        return createEncryptionResult(env, result.first, result.second);
        
    } catch (const std::exception& e) {
        handleException(env, e);
        return nullptr;
    }
}

JNIEXPORT jstring JNICALL Java_com_securemessaging_SecureCrypto_decryptMessage
(JNIEnv* env, jobject obj, jstring encryptedData, jstring keyHex) {
    try {
        std::string cppEncryptedData = jstringToString(env, encryptedData);
        std::string cppKeyHex = jstringToString(env, keyHex);
        
        SecureCryptoProcessor crypto;
        std::string decrypted = crypto.decryptMessage(cppEncryptedData, cppKeyHex);
        
        return stringToJstring(env, decrypted);
        
    } catch (const std::exception& e) {
        handleException(env, e);
        return nullptr;
    }
}

JNIEXPORT jboolean JNICALL Java_com_securemessaging_SecureCrypto_isValidKey
(JNIEnv* env, jobject obj, jstring keyHex) {
    try {
        std::string cppKeyHex = jstringToString(env, keyHex);
        SecureCryptoProcessor crypto;
        
        return crypto.isValidHexKey(cppKeyHex) ? JNI_TRUE : JNI_FALSE;
        
    } catch (const std::exception& e) {
        handleException(env, e);
        return JNI_FALSE;
    }
}

JNIEXPORT jobject JNICALL Java_com_securemessaging_SecureCrypto_getSystemInfo
(JNIEnv* env, jobject obj) {
    try {
        return createSystemInfo(env);
        
    } catch (const std::exception& e) {
        handleException(env, e);
        return nullptr;
    }
}

} // extern "C"
