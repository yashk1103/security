#ifndef SECURE_CRYPTO_PROCESSOR_H
#define SECURE_CRYPTO_PROCESSOR_H

#include <string>
#include <vector>
#include <memory>

/**
 * SecureCryptoProcessor - Core encryption/decryption functionality
 * 
 * Features:
 * - Dual AES-256 encryption (AES-512 equivalent security)
 * - 512-bit and 1488-bit key support
 * - Secure memory management with automatic cleanup
 * - Anti-timing attack protection
 * - No persistent key storage
 * - Direct key generation (no PBKDF2 vulnerabilities)
 */
class SecureCryptoProcessor {
public:
    SecureCryptoProcessor();
    ~SecureCryptoProcessor();

    // Delete copy constructor and assignment operator for security
    SecureCryptoProcessor(const SecureCryptoProcessor&) = delete;
    SecureCryptoProcessor& operator=(const SecureCryptoProcessor&) = delete;

    /**
     * Encrypt message with randomly generated key
     * @param message Plain text message to encrypt
     * @param use1488BitKey Whether to use 1488-bit key (default: false for 512-bit)
     * @return Pair of {base64_encrypted_data, hex_key}
     */
    std::pair<std::string, std::string> encryptMessage(const std::string& message, bool use1488BitKey = false);

    /**
     * Decrypt message with provided key
     * @param encryptedData Base64 encoded encrypted data
     * @param keyHex Hex encoded key (128 or 186 characters)
     * @return Decrypted plain text message
     */
    std::string decryptMessage(const std::string& encryptedData, const std::string& keyHex);

    /**
     * Validate hex key format
     * @param hex Hex string to validate
     * @return true if valid 512-bit or 1488-bit key
     */
    bool isValidHexKey(const std::string& hex);

private:
    // Key generation
    std::vector<unsigned char> generateSecureKey(bool use1488Bit = false);
    
    // Core crypto operations
    std::vector<unsigned char> performEncryption(const std::string& plaintext, const std::vector<unsigned char>& key);
    std::string performDecryption(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key);
    
    // Utility functions
    std::string toBase64(const std::vector<unsigned char>& data);
    std::vector<unsigned char> fromBase64(const std::string& encoded);
    std::string toHex(const std::vector<unsigned char>& data);
    std::vector<unsigned char> fromHex(const std::string& hex);
    
    // Security functions
    void secureWipe(std::vector<unsigned char>& data);
    void secureWipe(std::string& data);
    void addRandomDelay();
    
    // Key validation
    bool isValid512BitKey(const std::string& hex);
    bool isValid1488BitKey(const std::string& hex);
    bool isValidHexCharacter(char c);
};

#endif // SECURE_CRYPTO_PROCESSOR_H
