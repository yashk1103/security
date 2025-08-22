package com.securemessaging;

/**
 * Simple test for basic JNI functionality
 */
public class SimpleTest {
    
    public static void main(String[] args) {
        System.out.println("=== SIMPLE SECURE CRYPTO TEST ===");
        
        try {
            SecureCrypto crypto = new SecureCrypto();
            
            // Test JNI connection first
            System.out.println("Testing JNI connection...");
            String connectionTest = crypto.testConnection();
            System.out.println("Connection test result: " + connectionTest);
            
            // Test basic encryption/decryption
            String message = "Hello from Java to C++ via JNI!";
            System.out.println("Original: " + message);
            
            EncryptionResult result = crypto.encryptMessage(message, false);
            System.out.println("Encrypted data length: " + result.getEncryptedData().length());
            System.out.println("Key length: " + result.getKey().length());
            
            String decrypted = crypto.decryptMessage(result.getEncryptedData(), result.getKey());
            System.out.println("Decrypted: " + decrypted);
            
            if (message.equals(decrypted)) {
                System.out.println("SUCCESS: Encryption/Decryption working perfectly!");
            } else {
                System.out.println("FAILED: Messages don't match");
            }
            
            // Test system info
            SystemInfo info = crypto.getSystemInfo();
            System.out.println("System: " + info);
            
        } catch (Exception e) {
            System.err.println("Test failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
