#include "interactive_secure_message.h"
#include <iostream>
#include <string>

int main() {
    try {
        std::string message, password;
        
        std::cout << "=== INTERACTIVE SECURE MESSAGE DEMO ===\n\n";
        
        // Get user input for message
        std::cout << "Enter your secret message: ";
        std::getline(std::cin, message);
        
        if (message.empty()) {
            message = "Project funding is approved.";
            std::cout << "Using default message: \"" << message << "\"\n";
        }
        
        // Get user input for password
        std::cout << "Enter your password (or press Enter for default): ";
        std::getline(std::cin, password);
        
        if (password.empty()) {
            password = "my-super-secret-key";
            std::cout << "Using default password: \"" << password << "\"\n";
        }
        
        std::cout << "\n=== CRYPTOGRAPHIC EXPLANATION ===\n";
        std::cout << "PASSWORD vs KEY:\n";
        std::cout << "- Password: \"" << password << "\" (human-readable)\n";
        std::cout << "- Key: Will be derived using PBKDF2 (cryptographically strong)\n";
        std::cout << "- AES-512: Custom implementation using dual AES-256 encryption\n\n";
        
        SecureMessaging::InteractiveSecureMessage interactive(password);
        
        std::cout << "Message: \"" << message << "\"\n";
        std::cout << "Password: \"" << password << "\"\n";
        
        interactive.runInteractiveEncryption(message);
        
        std::cout << "\nWould you like to test decryption? (y/n): ";
        std::string choice;
        std::getline(std::cin, choice);
        
        if (choice == "y" || choice == "Y") {
            std::cout << "\nEnter the Base64 encrypted message: ";
            std::string encryptedData;
            std::getline(std::cin, encryptedData);
            
            SecureMessaging::InteractiveSecureMessage receiver(password);
            receiver.runInteractiveDecryption(encryptedData);
        }
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
