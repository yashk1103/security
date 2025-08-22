package com.securemessaging;

/**
 * Simple test to verify JNI connection is working
 */
public class JNIConnectionTest {
    
    public static void main(String[] args) {
        System.out.println("Testing JNI connection...");
        
        try {
            SecureCrypto crypto = new SecureCrypto();
            System.out.println("SecureCrypto instance created successfully");
            
            // Test the simple connection method
            String result = crypto.testConnection();
            System.out.println("testConnection() result: " + result);
            
            System.out.println("JNI connection test completed successfully!");
            
        } catch (Exception e) {
            System.err.println("JNI connection test failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
