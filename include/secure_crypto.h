#ifndef SECURE_CRYPTO_H
#define SECURE_CRYPTO_H

#include <string>
#include <vector>
#include <memory>

namespace SecureCrypto {

/**
 * High-security cryptographic processor
 * - No persistent key storage
 * - No PBKDF2 (direct key generation)
 * - No step-by-step process
 * - Immediate secure memory wiping
 * - Protection against timing attacks
 */
class CryptoProcessor {
public:
    CryptoProcessor();
    ~CryptoProcessor();
    
    // Delete copy constructor and assignment operator for security
    CryptoProcessor(const CryptoProcessor&) = delete;
    CryptoProcessor& operator=(const CryptoProcessor&) = delete;
    
    /**
     * Encrypt message with randomly generated key
     * @param message Plain text message to encrypt
     * @param use1488BitKey Whether to use 1488-bit key (default: false for 512-bit)
     * @return Pair of {encrypted_data_base64, key_hex}
     * @throws std::runtime_error on encryption failure
     */
    std::pair<std::string, std::string> encryptMessage(const std::string& message, bool use1488BitKey = false);
    
    /**
     * Decrypt message using provided key
     * @param encryptedData Base64 encoded encrypted data
     * @param keyHex Hex encoded key (supports 512-bit or 1488-bit keys)
     * @return Decrypted plain text message
     * @throws std::runtime_error on decryption failure or invalid key
     */
    std::string decryptMessage(const std::string& encryptedData, const std::string& keyHex);

private:
    // Secure random key generation (512-bit or 1488-bit)
    std::vector<unsigned char> generateSecureKey(bool use1488Bit = false);
    
    // Dual AES-256 encryption (AES-512 equivalent)
    std::vector<unsigned char> performEncryption(const std::string& plaintext, 
                                                const std::vector<unsigned char>& key);
    
    // Dual AES-256 decryption 
    std::string performDecryption(const std::vector<unsigned char>& cipherdata,
                                 const std::vector<unsigned char>& key);
    
    // Secure utility functions
    std::string toBase64(const std::vector<unsigned char>& data);
    std::vector<unsigned char> fromBase64(const std::string& encoded);
    std::string toHex(const std::vector<unsigned char>& data);
    std::vector<unsigned char> fromHex(const std::string& hex);
    
    // Security functions
    void secureWipe(std::vector<unsigned char>& data);
    void secureWipe(std::string& data);
    bool isValidHexKey(const std::string& hex);
    bool isValid512BitKey(const std::string& hex);
    bool isValid1488BitKey(const std::string& hex);
    
    // Anti-timing attack delay
    void addRandomDelay();
};

} // namespace SecureCrypto

#endif // SECURE_CRYPTO_H
