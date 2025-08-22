package com.securemessaging;

/**
 * Java interface to the Secure Crypto C++ library
 * Provides AES-512 equivalent encryption using dual AES-256 layers
 */
public class SecureCrypto {
    
    // Load the native library
    static {
        try {
            System.out.println("Attempting to load secure_crypto_jni library...");
            System.loadLibrary("secure_crypto_jni");
            System.out.println("Successfully loaded secure_crypto_jni library!");
        } catch (UnsatisfiedLinkError e) {
            System.err.println("Failed to load secure_crypto_jni library: " + e.getMessage());
            System.err.println("Library path: " + System.getProperty("java.library.path"));
            throw e;
        }
    }
    
    /**
     * Simple test method to verify JNI connection
     * @return test string from C++
     */
    public native String testConnection();
    
    /**
     * Encrypt a message using secure random key generation
     * @param message The plain text message to encrypt
     * @param use1488BitKey Whether to use 1488-bit key (true) or 512-bit key (false)
     * @return EncryptionResult containing encrypted data and key
     */
    public native EncryptionResult encryptMessage(String message, boolean use1488BitKey);
    
    /**
     * Decrypt a message using the provided key
     * @param encryptedData Base64 encoded encrypted data
     * @param keyHex Hex encoded key (128 or 186 characters)
     * @return Decrypted plain text message
     * @throws SecurityException if decryption fails
     */
    public native String decryptMessage(String encryptedData, String keyHex) throws SecurityException;
    
    /**
     * Validate if a hex key is in correct format
     * @param keyHex The hex key to validate
     * @return true if key is valid (128 or 186 hex characters)
     */
    public native boolean isValidKey(String keyHex);
    
    /**
     * Get information about the crypto system
     * @return SystemInfo containing version and capabilities
     */
    public native SystemInfo getSystemInfo();
}
