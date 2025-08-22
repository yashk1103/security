#include "../include/secure_crypto_processor.h"
#include <iostream>
#include <string>
#include <sstream>
#include <limits>
#include <ios>

#ifdef _WIN32
#define NOMINMAX  // Prevent Windows.h from defining min/max macros
#include <windows.h>
#endif

// ================================
// USER INTERFACE FUNCTIONS
// ================================

void displayMenu() {
    std::cout << "\n=== SECURE CRYPTO PROCESSOR (DUAL AES-256) ===" << std::endl;
    std::cout << "1. Encrypt Message (512-bit key)" << std::endl;
    std::cout << "2. Encrypt Message (1488-bit key)" << std::endl;
    std::cout << "3. Decrypt Message" << std::endl;
    std::cout << "4. System Information" << std::endl;
    std::cout << "5. Exit" << std::endl;
    std::cout << "Choose an option (1-5): ";
}

void displaySystemInfo() {
    std::cout << "\n=== SYSTEM INFORMATION ===" << std::endl;
    std::cout << "Algorithm: Dual AES-256 (AES-512 equivalent security)" << std::endl;
    std::cout << "Key Sizes: 512-bit and 1488-bit" << std::endl;
    std::cout << "Features:" << std::endl;
    std::cout << "  ✓ Secure Memory Management" << std::endl;
    std::cout << "  ✓ Anti-Timing Attack Protection" << std::endl;
    std::cout << "  ✓ Direct Key Generation (No PBKDF2)" << std::endl;
    std::cout << "  ✓ Base64 Encoding for Safe Transmission" << std::endl;
    std::cout << "  ✓ Automatic Secure Memory Wiping" << std::endl;
    
#ifdef _WIN32
    std::cout << "Platform: Windows" << std::endl;
#else
    std::cout << "Platform: Unix/Linux" << std::endl;
#endif
}

std::string getMultilineInput(const std::string& prompt) {
    std::cout << prompt << std::endl;
    std::cout << "(Press Enter twice to finish)" << std::endl;
    
    std::string result;
    std::string line;
    int emptyLines = 0;
    
    while (std::getline(std::cin, line)) {
        if (line.empty()) {
            emptyLines++;
            if (emptyLines >= 2) break;
        } else {
            emptyLines = 0;
            if (!result.empty()) result += "\n";
            result += line;
        }
    }
    
    return result;
}

void encryptMessage(SecureCryptoProcessor& crypto, bool use1488BitKey) {
    try {
        std::string keyType = use1488BitKey ? "1488-bit" : "512-bit";
        std::cout << "\n=== ENCRYPT MESSAGE (" << keyType << " key) ===" << std::endl;
        
        std::string message = getMultilineInput("Enter your message to encrypt:");
        
        if (message.empty()) {
            std::cout << "Error: Message cannot be empty!" << std::endl;
            return;
        }
        
        std::cout << "\nEncrypting..." << std::endl;
        
        auto result = crypto.encryptMessage(message, use1488BitKey);
        
        std::cout << "\n=== ENCRYPTION SUCCESSFUL ===" << std::endl;
        std::cout << "Original message length: " << message.length() << " bytes" << std::endl;
        std::cout << "Encrypted data length: " << result.first.length() << " characters (Base64)" << std::endl;
        std::cout << "Key length: " << result.second.length() << " characters (hex)" << std::endl;
        std::cout << "\nEncrypted Data (Base64):" << std::endl;
        std::cout << result.first << std::endl;
        std::cout << "\nEncryption Key (hex):" << std::endl;
        std::cout << result.second << std::endl;
        std::cout << "\n⚠️  IMPORTANT: Store this key securely! Without it, decryption is impossible." << std::endl;
        
    } catch (const std::exception& e) {
        std::cout << "Encryption failed: " << e.what() << std::endl;
    }
}

void decryptMessage(SecureCryptoProcessor& crypto) {
    try {
        std::cout << "\n=== DECRYPT MESSAGE ===" << std::endl;
        
        std::string encryptedData = getMultilineInput("Enter the encrypted data (Base64):");
        
        if (encryptedData.empty()) {
            std::cout << "Error: Encrypted data cannot be empty!" << std::endl;
            return;
        }
        
        std::cout << "Enter the decryption key (hex): ";
        std::string key;
        std::getline(std::cin, key);
        
        if (key.empty()) {
            std::cout << "Error: Key cannot be empty!" << std::endl;
            return;
        }
        
        std::cout << "\nDecrypting..." << std::endl;
        
        std::string decryptedMessage = crypto.decryptMessage(encryptedData, key);
        
        std::cout << "\n=== DECRYPTION SUCCESSFUL ===" << std::endl;
        std::cout << "Decrypted message:" << std::endl;
        std::cout << decryptedMessage << std::endl;
        
    } catch (const std::exception& e) {
        std::cout << "Decryption failed: " << e.what() << std::endl;
        std::cout << "\nTroubleshooting:" << std::endl;
        std::cout << "* Check that the key is correct" << std::endl;
        std::cout << "* Ensure the encrypted data is valid Base64" << std::endl;
        std::cout << "* Verify the data hasn't been corrupted" << std::endl;
    }
}

int getChoice() {
    int choice;
    while (!(std::cin >> choice) || choice < 1 || choice > 5) {
        std::cout << "Invalid input. Please enter a number between 1 and 5: ";
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    }
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    return choice;
}

// ================================
// MAIN FUNCTION
// ================================

int main() {
    try {
        SecureCryptoProcessor crypto;
        
        std::cout << "Secure Crypto Processor v1.0" << std::endl;
        std::cout << "Dual AES-256 Encryption System" << std::endl;
        
        int choice;
        do {
            displayMenu();
            choice = getChoice();
            
            switch (choice) {
                case 1:
                    encryptMessage(crypto, false); // 512-bit key
                    break;
                case 2:
                    encryptMessage(crypto, true);  // 1488-bit key
                    break;
                case 3:
                    decryptMessage(crypto);
                    break;
                case 4:
                    displaySystemInfo();
                    break;
                case 5:
                    std::cout << "\nGoodbye! All cryptographic data has been securely wiped." << std::endl;
                    break;
                default:
                    std::cout << "Invalid choice!" << std::endl;
            }
        } while (choice != 5);
        
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }
}
