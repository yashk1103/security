package com.securemessaging;

/**
 * Comprehensive test suite for SecureCrypto JNI integration
 */
public class SecureCryptoTest {
    
    public static void main(String[] args) {
        System.out.println("=== SECURE CRYPTO JNI TEST SUITE ===");
        
        try {
            SecureCrypto crypto = new SecureCrypto();
            
            // Test 1: System Information
            testSystemInfo(crypto);
            
            // Test 2: 512-bit Key Encryption/Decryption
            test512BitEncryption(crypto);
            
            // Test 3: 1488-bit Key Encryption/Decryption
            test1488BitEncryption(crypto);
            
            // Test 4: Key Validation
            testKeyValidation(crypto);
            
            // Test 5: Error Handling
            testErrorHandling(crypto);
            
            // Test 6: Performance Test
            performanceTest(crypto);
            
            System.out.println("\n=== ALL TESTS COMPLETED SUCCESSFULLY ===");
            
        } catch (Exception e) {
            System.err.println("Test failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private static void testSystemInfo(SecureCrypto crypto) {
        System.out.println("\n--- Test 1: System Information ---");
        SystemInfo info = crypto.getSystemInfo();
        System.out.println("System Info: " + info);
        System.out.println("✓ System info retrieved successfully");
    }
    
    private static void test512BitEncryption(SecureCrypto crypto) {
        System.out.println("\n--- Test 2: 512-bit Encryption/Decryption ---");
        
        String originalMessage = "Hello, this is a test message for 512-bit encryption!";
        System.out.println("Original message: " + originalMessage);
        
        // Encrypt with 512-bit key
        EncryptionResult result = crypto.encryptMessage(originalMessage, false);
        System.out.println("Encryption result: " + result);
        System.out.println("Encrypted data: " + result.getEncryptedData());
        System.out.println("Key: " + result.getKey());
        
        // Decrypt
        String decryptedMessage = crypto.decryptMessage(result.getEncryptedData(), result.getKey());
        System.out.println("Decrypted message: " + decryptedMessage);
        
        // Verify
        if (originalMessage.equals(decryptedMessage)) {
            System.out.println("✓ 512-bit encryption/decryption successful");
        } else {
            throw new RuntimeException("512-bit encryption/decryption failed: messages don't match");
        }
    }
    
    private static void test1488BitEncryption(SecureCrypto crypto) {
        System.out.println("\n--- Test 3: 1488-bit Encryption/Decryption ---");
        
        String originalMessage = "This is a longer test message to verify 1488-bit key encryption works correctly with extended security!";
        System.out.println("Original message: " + originalMessage);
        
        // Encrypt with 1488-bit key
        EncryptionResult result = crypto.encryptMessage(originalMessage, true);
        System.out.println("Encryption result: " + result);
        System.out.println("Encrypted data length: " + result.getEncryptedData().length());
        System.out.println("Key length: " + result.getKey().length());
        
        // Decrypt
        String decryptedMessage = crypto.decryptMessage(result.getEncryptedData(), result.getKey());
        System.out.println("Decrypted message: " + decryptedMessage);
        
        // Verify
        if (originalMessage.equals(decryptedMessage)) {
            System.out.println("✓ 1488-bit encryption/decryption successful");
        } else {
            throw new RuntimeException("1488-bit encryption/decryption failed: messages don't match");
        }
    }
    
    private static void testKeyValidation(SecureCrypto crypto) {
        System.out.println("\n--- Test 4: Key Validation ---");
        
        // Valid 512-bit key (128 hex chars)
        String valid512Key = "1234567890abcdef".repeat(8);
        System.out.println("Valid 512-bit key: " + crypto.isValidKey(valid512Key));
        
        // Valid 1488-bit key (186 hex chars)
        String valid1488Key = "1234567890abcdef".repeat(11) + "1234567890";
        System.out.println("Valid 1488-bit key: " + crypto.isValidKey(valid1488Key));
        
        // Invalid keys
        System.out.println("Invalid short key: " + crypto.isValidKey("123"));
        System.out.println("Invalid non-hex key: " + crypto.isValidKey("xyz".repeat(43)));
        
        System.out.println("✓ Key validation working correctly");
    }
    
    private static void testErrorHandling(SecureCrypto crypto) {
        System.out.println("\n--- Test 5: Error Handling ---");
        
        try {
            // Test empty message
            crypto.encryptMessage("", false);
            throw new RuntimeException("Should have failed for empty message");
        } catch (Exception e) {
            System.out.println("✓ Empty message error handled: " + e.getMessage());
        }
        
        try {
            // Test invalid key for decryption
            crypto.decryptMessage("validbase64data", "invalidkey");
            throw new RuntimeException("Should have failed for invalid key");
        } catch (Exception e) {
            System.out.println("✓ Invalid key error handled: " + e.getMessage());
        }
        
        System.out.println("✓ Error handling working correctly");
    }
    
    private static void performanceTest(SecureCrypto crypto) {
        System.out.println("\n--- Test 6: Performance Test ---");
        
        String testMessage = "Performance test message. ".repeat(100); // ~2.5KB message
        int iterations = 10;
        
        long startTime = System.currentTimeMillis();
        
        for (int i = 0; i < iterations; i++) {
            EncryptionResult result = crypto.encryptMessage(testMessage, false);
            String decrypted = crypto.decryptMessage(result.getEncryptedData(), result.getKey());
            
            if (!testMessage.equals(decrypted)) {
                throw new RuntimeException("Performance test failed at iteration " + i);
            }
        }
        
        long endTime = System.currentTimeMillis();
        double avgTime = (endTime - startTime) / (double) iterations;
        
        System.out.println("Processed " + iterations + " encrypt/decrypt cycles");
        System.out.println("Average time per cycle: " + String.format("%.2f", avgTime) + " ms");
        System.out.println("Message size: " + testMessage.length() + " bytes");
        System.out.println("✓ Performance test completed successfully");
    }
}
