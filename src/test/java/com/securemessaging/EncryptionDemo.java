package com.securemessaging;

/**
 * Interactive test for encryption and decryption using JNI
 */
public class EncryptionDemo {
    
    public static void main(String[] args) {
        System.out.println("=== Secure Messaging Encryption Demo ===\n");
        
        try {
            SecureCrypto crypto = new SecureCrypto();
            System.out.println("✓ JNI library loaded successfully\n");
            
            // Test messages
            String message1 = "Hello, this is a secret message!";
            String message2 = "This is a longer message that will be encrypted with maximum security using 1488-bit keys for ultimate protection.";
            
            // Demo 1: 512-bit encryption
            System.out.println("=== 512-bit Encryption Demo ===");
            System.out.println("Original message: " + message1);
            
            EncryptionResult result512 = crypto.encryptMessage(message1, false);
            System.out.println("✓ Encryption successful!");
            System.out.println("Encrypted data: " + result512.getEncryptedData());
            System.out.println("Key (hex): " + result512.getKey());
            System.out.println("Key length: " + result512.getKey().length() + " characters");
            
            // Decrypt back
            String decrypted512 = crypto.decryptMessage(result512.getEncryptedData(), result512.getKey());
            System.out.println("✓ Decryption successful!");
            System.out.println("Decrypted message: " + decrypted512);
            System.out.println("Match original: " + message1.equals(decrypted512));
            
            System.out.println("\n" + "=".repeat(50) + "\n");
            
            // Demo 2: 1488-bit encryption
            System.out.println("=== 1488-bit Encryption Demo ===");
            System.out.println("Original message: " + message2);
            
            EncryptionResult result1488 = crypto.encryptMessage(message2, true);
            System.out.println("✓ Encryption successful!");
            System.out.println("Encrypted data: " + result1488.getEncryptedData());
            System.out.println("Key (hex): " + result1488.getKey());
            System.out.println("Key length: " + result1488.getKey().length() + " characters");
            
            // Decrypt back
            String decrypted1488 = crypto.decryptMessage(result1488.getEncryptedData(), result1488.getKey());
            System.out.println("✓ Decryption successful!");
            System.out.println("Decrypted message: " + decrypted1488);
            System.out.println("Match original: " + message2.equals(decrypted1488));
            
            System.out.println("\n" + "=".repeat(50) + "\n");
            
            // Demo 3: Key validation
            System.out.println("=== Key Validation Demo ===");
            System.out.println("512-bit key valid: " + crypto.isValidKey(result512.getKey()));
            System.out.println("1488-bit key valid: " + crypto.isValidKey(result1488.getKey()));
            System.out.println("Invalid key valid: " + crypto.isValidKey("invalid_key_123"));
            
            System.out.println("\n" + "=".repeat(50) + "\n");
            
            // Demo 4: System information
            System.out.println("=== System Information ===");
            SystemInfo info = crypto.getSystemInfo();
            System.out.println("Algorithm: " + info.getAlgorithm());
            System.out.println("Version: " + info.getVersion());
            System.out.println("Supports 512-bit: " + info.supports512Bit());
            System.out.println("Supports 1488-bit: " + info.supports1488Bit());
            System.out.println("Security Features: " + info.getSecurityFeatures());
            
            System.out.println("\n🎉 All encryption/decryption operations completed successfully!");
            
        } catch (Exception e) {
            System.err.println("❌ Error during encryption demo: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
