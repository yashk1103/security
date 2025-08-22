package com.securemessaging;

import java.util.Scanner;

/**
 * Interactive encryption and decryption demo using JNI
 * Similar to the C++ secure_crypto.cpp application
 */
public class InteractiveSecureCrypto {
    
    private SecureCrypto crypto;
    private Scanner scanner;
    
    public InteractiveSecureCrypto() {
        this.crypto = new SecureCrypto();
        this.scanner = new Scanner(System.in);
    }
    
    public static void main(String[] args) {
        InteractiveSecureCrypto app = new InteractiveSecureCrypto();
        app.run();
    }
    
    public void run() {
        System.out.println("=== SECURE CRYPTO PROCESSOR (DUAL AES-256) ===");
        System.out.println("Java JNI Interface to C++ Cryptographic Library");
        System.out.println("Loaded successfully: " + crypto.testConnection());
        
        while (true) {
            displayMenu();
            int choice = getChoice();
            
            switch (choice) {
                case 1:
                    encryptMessage(false); // 512-bit key
                    break;
                case 2:
                    encryptMessage(true);  // 1488-bit key
                    break;
                case 3:
                    decryptMessage();
                    break;
                case 4:
                    displaySystemInfo();
                    break;
                case 5:
                    System.out.println("\\nThank you for using Secure Crypto Processor!");
                    return;
                default:
                    System.out.println("Invalid choice. Please try again.");
            }
        }
    }
    
    private void displayMenu() {
        System.out.println("\\n=== SECURE CRYPTO PROCESSOR (DUAL AES-256) ===");
        System.out.println("1. Encrypt Message (512-bit key)");
        System.out.println("2. Encrypt Message (1488-bit key)");
        System.out.println("3. Decrypt Message");
        System.out.println("4. System Information");
        System.out.println("5. Exit");
        System.out.print("Choose an option (1-5): ");
    }
    
    private int getChoice() {
        try {
            int choice = Integer.parseInt(scanner.nextLine().trim());
            return choice;
        } catch (NumberFormatException e) {
            return -1;
        }
    }
    
    private String getMultilineInput(String prompt) {
        System.out.println(prompt);
        System.out.println("(Press Enter on empty line to finish)");
        
        StringBuilder result = new StringBuilder();
        String line;
        
        while (!(line = scanner.nextLine()).isEmpty()) {
            if (result.length() > 0) {
                result.append("\\n");
            }
            result.append(line);
        }
        
        return result.toString();
    }
    
    private void encryptMessage(boolean use1488BitKey) {
        try {
            String keyType = use1488BitKey ? "1488-bit" : "512-bit";
            System.out.println("\\n=== ENCRYPT MESSAGE (" + keyType + " key) ===");
            
            String message = getMultilineInput("Enter your message to encrypt:");
            
            if (message.trim().isEmpty()) {
                System.out.println("Error: Message cannot be empty!");
                return;
            }
            
            System.out.println("\\nEncrypting...");
            
            EncryptionResult result = crypto.encryptMessage(message, use1488BitKey);
            
            if (result != null) {
                System.out.println("\\n=== ENCRYPTION SUCCESSFUL ===");
                System.out.println("Original message length: " + message.length() + " bytes");
                System.out.println("Encrypted data length: " + result.getEncryptedData().length() + " characters (Base64)");
                System.out.println("Key length: " + result.getKey().length() + " characters (hex)");
                System.out.println("Key bits: " + result.getKeyBits() + "-bit key");
                System.out.println("\\nEncrypted Data (Base64):");
                System.out.println(result.getEncryptedData());
                System.out.println("\\nEncryption Key (hex):");
                System.out.println(result.getKey());
                System.out.println("\\n[WARNING] IMPORTANT: Store this key securely! Without it, decryption is impossible.");
            } else {
                System.out.println("[ERROR] Encryption failed - result is null");
            }
            
        } catch (Exception e) {
            System.out.println("[ERROR] Encryption failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private void decryptMessage() {
        try {
            System.out.println("\\n=== DECRYPT MESSAGE ===");
            
            String encryptedData = getMultilineInput("Enter the encrypted data (Base64):");
            
            if (encryptedData.trim().isEmpty()) {
                System.out.println("Error: Encrypted data cannot be empty!");
                return;
            }
            
            System.out.print("Enter the decryption key (hex): ");
            String key = scanner.nextLine().trim();
            
            if (key.isEmpty()) {
                System.out.println("Error: Key cannot be empty!");
                return;
            }
            
            // Validate key format
            if (!crypto.isValidKey(key)) {
                System.out.println("Error: Invalid key format! Key must be 128 or 186 hex characters.");
                return;
            }
            
            System.out.println("\\nDecrypting...");
            
            String decryptedMessage = crypto.decryptMessage(encryptedData, key);
            
            System.out.println("\\n=== DECRYPTION SUCCESSFUL ===");
            System.out.println("Decrypted message length: " + decryptedMessage.length() + " bytes");
            System.out.println("\\nDecrypted Message:");
            System.out.println("\"" + decryptedMessage + "\"");
            
        } catch (SecurityException e) {
            System.out.println("[ERROR] Decryption failed: Invalid key or corrupted data");
            System.out.println("Details: " + e.getMessage());
        } catch (Exception e) {
            System.out.println("[ERROR] Decryption failed: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private void displaySystemInfo() {
        try {
            System.out.println("\\n=== SYSTEM INFORMATION ===");
            
            SystemInfo info = crypto.getSystemInfo();
            if (info != null) {
                System.out.println("Algorithm: " + info.getAlgorithm());
                System.out.println("Version: " + info.getVersion());
                System.out.println("Key Sizes: 512-bit and 1488-bit");
                System.out.println("Supports 512-bit: " + info.supports512Bit());
                System.out.println("Supports 1488-bit: " + info.supports1488Bit());
                System.out.println("Security Features: " + info.getSecurityFeatures());
                System.out.println("Features:");
                System.out.println("  * Secure Memory Management");
                System.out.println("  * Anti-Timing Attack Protection");
                System.out.println("  * Direct Key Generation (No PBKDF2)");
                System.out.println("  * Base64 Encoding for Safe Transmission");
                System.out.println("  * Automatic Secure Memory Wiping");
                System.out.println("Platform: Windows (via JNI)");
                System.out.println("Interface: Java JNI → C++ OpenSSL");
            } else {
                System.out.println("[ERROR] Failed to retrieve system information");
            }
            
        } catch (Exception e) {
            System.out.println("[ERROR] Failed to get system info: " + e.getMessage());
        }
    }
}
