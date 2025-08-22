package com.securemessaging;

/**
 * Result of encryption operation
 */
public class EncryptionResult {
    private final String encryptedData;
    private final String key;
    private final int keyBits;
    
    public EncryptionResult(String encryptedData, String key, int keyBits) {
        this.encryptedData = encryptedData;
        this.key = key;
        this.keyBits = keyBits;
    }
    
    /**
     * @return Base64 encoded encrypted data
     */
    public String getEncryptedData() {
        return encryptedData;
    }
    
    /**
     * @return Hex encoded encryption key
     */
    public String getKey() {
        return key;
    }
    
    /**
     * @return Key size in bits (512 or 1488)
     */
    public int getKeyBits() {
        return keyBits;
    }
    
    @Override
    public String toString() {
        return String.format("EncryptionResult{keyBits=%d, dataLength=%d, keyLength=%d}", 
                           keyBits, encryptedData.length(), key.length());
    }
}
