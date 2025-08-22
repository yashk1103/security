#include "../include/secure_crypto_processor.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <chrono>
#include <thread>
#include <random>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#ifdef _WIN32
#include <windows.h>
#endif

// ================================
// CONSTRUCTOR & DESTRUCTOR
// ================================

SecureCryptoProcessor::SecureCryptoProcessor() {
    // Initialize OpenSSL
    if (!RAND_status()) {
        throw std::runtime_error("OpenSSL random number generator not properly seeded");
    }
}

SecureCryptoProcessor::~SecureCryptoProcessor() {
    // Secure cleanup - nothing persistent to clean
}

// ================================
// PUBLIC INTERFACE METHODS
// ================================

std::pair<std::string, std::string> SecureCryptoProcessor::encryptMessage(const std::string& message, bool use1488BitKey) {
    if (message.empty()) {
        throw std::runtime_error("Cannot encrypt empty message");
    }

    // Generate secure random key
    auto key = generateSecureKey(use1488BitKey);

    try {
        // Perform dual AES-256 encryption
        auto encryptedData = performEncryption(message, key);

        // Convert to Base64 and hex
        std::string base64Data = toBase64(encryptedData);
        std::string hexKey = toHex(key);

        // Secure cleanup
        secureWipe(key);
        secureWipe(encryptedData);

        return {base64Data, hexKey};

    } catch (const std::exception& e) {
        secureWipe(key);
        throw;
    }
}

std::string SecureCryptoProcessor::decryptMessage(const std::string& encryptedData, const std::string& keyHex) {
    // Validate key format
    if (!isValidHexKey(keyHex)) {
        addRandomDelay(); // Anti-timing attack
        throw std::runtime_error("Invalid key format: must be 128 or 186 hex characters");
    }

    // Convert hex key to binary
    auto key = fromHex(keyHex);

    try {
        // Convert Base64 data to binary
        auto binaryData = fromBase64(encryptedData);

        // Perform dual AES-256 decryption
        std::string result = performDecryption(binaryData, key);

        // Secure cleanup
        secureWipe(key);
        secureWipe(binaryData);

        return result;

    } catch (const std::exception& e) {
        secureWipe(key);
        addRandomDelay(); // Anti-timing attack
        throw;
    }
}

bool SecureCryptoProcessor::isValidHexKey(const std::string& hex) {
    return isValid512BitKey(hex) || isValid1488BitKey(hex);
}

// ================================
// PRIVATE KEY GENERATION
// ================================

std::vector<unsigned char> SecureCryptoProcessor::generateSecureKey(bool use1488Bit) {
    size_t keySize = use1488Bit ? 93 : 64; // 1488-bit (93 bytes) or 512-bit (64 bytes)
    std::vector<unsigned char> key(keySize);

    // Generate cryptographically secure random key
    if (RAND_bytes(key.data(), static_cast<int>(keySize)) != 1) {
        secureWipe(key);
        throw std::runtime_error("Failed to generate secure random key");
    }

    return key;
}

// ================================
// PRIVATE ENCRYPTION METHODS
// ================================

std::vector<unsigned char> SecureCryptoProcessor::performEncryption(const std::string& plaintext, 
                                            const std::vector<unsigned char>& key) {
    if (key.size() != 64 && key.size() != 93) {
        throw std::runtime_error("Invalid key size for encryption (must be 512-bit or 1488-bit)");
    }

    // Generate random IV
    std::vector<unsigned char> iv(16);
    if (RAND_bytes(iv.data(), 16) != 1) {
        throw std::runtime_error("Failed to generate IV");
    }

    // First AES-256 encryption layer
    EVP_CIPHER_CTX* ctx1 = EVP_CIPHER_CTX_new();
    if (!ctx1) {
        throw std::runtime_error("Failed to create encryption context 1");
    }

    // Use first 32 bytes of key
    if (EVP_EncryptInit_ex(ctx1, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx1);
        throw std::runtime_error("Failed to initialize encryption layer 1");
    }

    // Allocate buffer for first encryption
    std::vector<unsigned char> buffer1(plaintext.length() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int len1, finalLen1 = 0;

    if (EVP_EncryptUpdate(ctx1, buffer1.data(), &len1,
                         reinterpret_cast<const unsigned char*>(plaintext.c_str()),
                         plaintext.length()) != 1) {
        EVP_CIPHER_CTX_free(ctx1);
        secureWipe(buffer1);
        throw std::runtime_error("Encryption layer 1 failed");
    }

    if (EVP_EncryptFinal_ex(ctx1, buffer1.data() + len1, &finalLen1) != 1) {
        EVP_CIPHER_CTX_free(ctx1);
        secureWipe(buffer1);
        throw std::runtime_error("Encryption layer 1 finalization failed");
    }

    buffer1.resize(len1 + finalLen1);
    EVP_CIPHER_CTX_free(ctx1);

    // Second AES-256 encryption layer
    EVP_CIPHER_CTX* ctx2 = EVP_CIPHER_CTX_new();
    if (!ctx2) {
        secureWipe(buffer1);
        throw std::runtime_error("Failed to create encryption context 2");
    }

    // Use last 32 bytes of key (or starting from byte 32 for larger keys)
    size_t secondKeyOffset = (key.size() > 64) ? 32 : (key.size() - 32);
    if (EVP_EncryptInit_ex(ctx2, EVP_aes_256_cbc(), nullptr, key.data() + secondKeyOffset, iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx2);
        secureWipe(buffer1);
        throw std::runtime_error("Failed to initialize encryption layer 2");
    }

    std::vector<unsigned char> buffer2(buffer1.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int len2, finalLen2 = 0;

    if (EVP_EncryptUpdate(ctx2, buffer2.data(), &len2, buffer1.data(), buffer1.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx2);
        secureWipe(buffer1);
        secureWipe(buffer2);
        throw std::runtime_error("Encryption layer 2 failed");
    }

    if (EVP_EncryptFinal_ex(ctx2, buffer2.data() + len2, &finalLen2) != 1) {
        EVP_CIPHER_CTX_free(ctx2);
        secureWipe(buffer1);
        secureWipe(buffer2);
        throw std::runtime_error("Encryption layer 2 finalization failed");
    }

    buffer2.resize(len2 + finalLen2);
    EVP_CIPHER_CTX_free(ctx2);

    // Combine IV + encrypted data
    std::vector<unsigned char> result;
    result.reserve(16 + buffer2.size());
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), buffer2.begin(), buffer2.end());

    // Secure cleanup
    secureWipe(buffer1);
    secureWipe(buffer2);

    return result;
}

std::string SecureCryptoProcessor::performDecryption(const std::vector<unsigned char>& cipherdata,
                                             const std::vector<unsigned char>& key) {
    if (key.size() != 64 && key.size() != 93) {
        throw std::runtime_error("Invalid key size for decryption (must be 512-bit or 1488-bit)");
    }

    if (cipherdata.size() < 16) {
        throw std::runtime_error("Invalid encrypted data: too short");
    }

    // Extract IV and ciphertext
    std::vector<unsigned char> iv(cipherdata.begin(), cipherdata.begin() + 16);
    std::vector<unsigned char> encrypted(cipherdata.begin() + 16, cipherdata.end());

    // First decryption layer (reverse order - second key first)
    EVP_CIPHER_CTX* ctx1 = EVP_CIPHER_CTX_new();
    if (!ctx1) {
        throw std::runtime_error("Failed to create decryption context 1");
    }

    size_t secondKeyOffset = (key.size() > 64) ? 32 : (key.size() - 32);
    if (EVP_DecryptInit_ex(ctx1, EVP_aes_256_cbc(), nullptr, key.data() + secondKeyOffset, iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx1);
        throw std::runtime_error("Failed to initialize decryption layer 1");
    }

    std::vector<unsigned char> buffer1(encrypted.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int len1, finalLen1 = 0;

    if (EVP_DecryptUpdate(ctx1, buffer1.data(), &len1, encrypted.data(), encrypted.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx1);
        secureWipe(buffer1);
        addRandomDelay(); // Anti-timing attack
        throw std::runtime_error("Decryption layer 1 failed");
    }

    if (EVP_DecryptFinal_ex(ctx1, buffer1.data() + len1, &finalLen1) != 1) {
        EVP_CIPHER_CTX_free(ctx1);
        secureWipe(buffer1);
        addRandomDelay(); // Anti-timing attack
        throw std::runtime_error("Decryption layer 1 finalization failed");
    }

    buffer1.resize(len1 + finalLen1);
    EVP_CIPHER_CTX_free(ctx1);

    // Second decryption layer (first key)
    EVP_CIPHER_CTX* ctx2 = EVP_CIPHER_CTX_new();
    if (!ctx2) {
        secureWipe(buffer1);
        throw std::runtime_error("Failed to create decryption context 2");
    }

    if (EVP_DecryptInit_ex(ctx2, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx2);
        secureWipe(buffer1);
        throw std::runtime_error("Failed to initialize decryption layer 2");
    }

    std::vector<unsigned char> buffer2(buffer1.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int len2, finalLen2 = 0;

    if (EVP_DecryptUpdate(ctx2, buffer2.data(), &len2, buffer1.data(), buffer1.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx2);
        secureWipe(buffer1);
        secureWipe(buffer2);
        addRandomDelay(); // Anti-timing attack
        throw std::runtime_error("Decryption layer 2 failed");
    }

    if (EVP_DecryptFinal_ex(ctx2, buffer2.data() + len2, &finalLen2) != 1) {
        EVP_CIPHER_CTX_free(ctx2);
        secureWipe(buffer1);
        secureWipe(buffer2);
        addRandomDelay(); // Anti-timing attack
        throw std::runtime_error("Decryption layer 2 finalization failed");
    }

    buffer2.resize(len2 + finalLen2);
    EVP_CIPHER_CTX_free(ctx2);

    // Convert to string
    std::string result(buffer2.begin(), buffer2.end());

    // Secure cleanup
    secureWipe(buffer1);
    secureWipe(buffer2);

    return result;
}

// ================================
// PRIVATE UTILITY METHODS
// ================================

std::string SecureCryptoProcessor::toBase64(const std::vector<unsigned char>& data) {
    if (data.empty()) return "";

    size_t encodedLength = ((data.size() + 2) / 3) * 4;
    std::vector<unsigned char> encoded(encodedLength + 1);

    if (EVP_EncodeBlock(encoded.data(), data.data(), data.size()) < 0) {
        throw std::runtime_error("Base64 encoding failed");
    }

    return std::string(encoded.begin(), encoded.end() - 1);
}

std::vector<unsigned char> SecureCryptoProcessor::fromBase64(const std::string& encoded) {
    if (encoded.empty()) return {};

    size_t decodedLength = (encoded.length() * 3) / 4;
    std::vector<unsigned char> decoded(decodedLength + 16); // Extra space for safety

    int actualLength = EVP_DecodeBlock(decoded.data(),
                                      reinterpret_cast<const unsigned char*>(encoded.c_str()),
                                      encoded.length());

    if (actualLength < 0) {
        throw std::runtime_error("Invalid Base64 data");
    }

    // Adjust for Base64 padding
    if (encoded.length() >= 2) {
        if (encoded[encoded.length()-1] == '=') actualLength--;
        if (encoded[encoded.length()-2] == '=') actualLength--;
    }

    decoded.resize(actualLength);
    return decoded;
}

std::string SecureCryptoProcessor::toHex(const std::vector<unsigned char>& data) {
    std::ostringstream oss;
    for (unsigned char byte : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return oss.str();
}

std::vector<unsigned char> SecureCryptoProcessor::fromHex(const std::string& hex) {
    if (hex.length() % 2 != 0) {
        throw std::runtime_error("Invalid hex string: odd length");
    }

    std::vector<unsigned char> result;
    result.reserve(hex.length() / 2);

    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoul(byteString, nullptr, 16));
        result.push_back(byte);
    }

    return result;
}

// ================================
// PRIVATE SECURITY METHODS
// ================================

void SecureCryptoProcessor::secureWipe(std::vector<unsigned char>& data) {
    if (!data.empty()) {
#ifdef _WIN32
        SecureZeroMemory(data.data(), data.size());
#else
        explicit_bzero(data.data(), data.size());
#endif
        data.clear();
        data.shrink_to_fit();
    }
}

void SecureCryptoProcessor::secureWipe(std::string& data) {
    if (!data.empty()) {
#ifdef _WIN32
        SecureZeroMemory(&data[0], data.size());
#else
        explicit_bzero(&data[0], data.size());
#endif
        data.clear();
        data.shrink_to_fit();
    }
}

void SecureCryptoProcessor::addRandomDelay() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(50, 150);
    std::this_thread::sleep_for(std::chrono::milliseconds(dis(gen)));
}

// ================================
// PRIVATE KEY VALIDATION METHODS
// ================================

bool SecureCryptoProcessor::isValid512BitKey(const std::string& hex) {
    return hex.length() == 128 && std::all_of(hex.begin(), hex.end(), 
                                              [this](char c) { return isValidHexCharacter(c); });
}

bool SecureCryptoProcessor::isValid1488BitKey(const std::string& hex) {
    return hex.length() == 186 && std::all_of(hex.begin(), hex.end(), 
                                              [this](char c) { return isValidHexCharacter(c); });
}

bool SecureCryptoProcessor::isValidHexCharacter(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}
