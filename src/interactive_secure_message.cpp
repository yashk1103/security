#include "interactive_secure_message.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <cstring>
#include <vector>
#include <utility>
#include <algorithm>

namespace SecureMessaging {

InteractiveSecureMessage::InteractiveSecureMessage(const std::string& password) : password_(password) {
    salt_ = generateRandomSalt();
}

void InteractiveSecureMessage::runInteractiveEncryption(const std::string& message) {
    std::cout << "\n=== SENDER SIDE: CREATING SECURE MESSAGE ===\n\n";
    
    std::string step1_result = step1_startMessage(message);
    if (!waitForUserInput()) return;
    
    std::string step2_result = step2_generateHash(step1_result);
    if (!waitForUserInput()) return;
    
    std::string step3_result = step3_combineMessageHash(step1_result, step2_result);
    if (!waitForUserInput()) return;
    
    std::vector<unsigned char> step4_result = step4_generateKey();
    if (!waitForUserInput()) return;
    
    std::vector<unsigned char> iv(16);
    RAND_bytes(iv.data(), 16);
    std::vector<unsigned char> step5_result = step5_encrypt(step3_result, step4_result, iv);
    if (!waitForUserInput()) return;
    
    std::vector<unsigned char> combined_data;
    combined_data.insert(combined_data.end(), salt_.begin(), salt_.end());
    combined_data.insert(combined_data.end(), iv.begin(), iv.end());
    combined_data.insert(combined_data.end(), step5_result.begin(), step5_result.end());
    
    std::string final_result = step6_encodeBase64(combined_data);
    
    std::cout << "\n[SUCCESS] TRANSMISSION READY:\n";
    std::cout << "Base64 Message: " << final_result << "\n\n";
}

void InteractiveSecureMessage::runInteractiveDecryption(const std::string& encryptedData) {
    std::cout << "\n=== RECEIVER SIDE: VERIFYING AND READING MESSAGE ===\n\n";
    
    std::string step1r_result = step1r_receiveBase64(encryptedData);
    if (!waitForUserInput()) return;
    
    std::vector<unsigned char> step2r_result = step2r_decodeBase64(step1r_result);
    if (!waitForUserInput()) return;
    
    if (step2r_result.size() < 48) throw std::runtime_error("Invalid data size");
    
    std::vector<unsigned char> received_salt(step2r_result.begin(), step2r_result.begin() + 32);
    std::vector<unsigned char> iv(step2r_result.begin() + 32, step2r_result.begin() + 48);
    std::vector<unsigned char> ciphertext(step2r_result.begin() + 48, step2r_result.end());
    
    salt_ = received_salt;
    std::vector<unsigned char> step3r_result = step3r_generateKey();
    if (!waitForUserInput()) return;
    
    std::string step4r_result = step4r_decrypt(ciphertext, step3r_result, iv);
    if (!waitForUserInput()) return;
    
    auto step5r_result = step5r_splitMessageHash(step4r_result);
    if (!waitForUserInput()) return;
    
    std::string step6r_result = step6r_verifyHash(step5r_result.first);
    if (!waitForUserInput()) return;
    
    bool step7r_result = step7r_compareHashes(step5r_result.second, step6r_result);
    
    std::cout << "\n[SUCCESS] FINAL RESULT:\n";
    std::cout << "Decrypted Message: \"" << step5r_result.first << "\"\n";
    std::cout << "Integrity Status: " << (step7r_result ? "VERIFIED [OK]" : "FAILED [ERROR]") << "\n\n";
}

std::string InteractiveSecureMessage::step1_startMessage(const std::string& message) {
    displayStep("STEP 1: Start with Original Message", 
                "None (starting data)", 
                "\"" + message + "\"");
    return message;
}

std::string InteractiveSecureMessage::step2_generateHash(const std::string& message) {
    unsigned char hash[64];  // SHA512 produces 64 bytes
    unsigned int hash_len = 0;
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create hash context");
    }
    
    if (EVP_DigestInit_ex(ctx, EVP_sha512(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, message.c_str(), message.length()) != 1 ||
        EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to generate hash");
    }
    
    EVP_MD_CTX_free(ctx);
    
    std::stringstream ss;
    for (unsigned int i = 0; i < hash_len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    
    std::string result = ss.str();
    displayStep("STEP 2: Generate SHA-512 Hash for Integrity", 
                "\"" + message + "\"", 
                result.substr(0, 32) + "...");
    return result;
}

std::string InteractiveSecureMessage::step3_combineMessageHash(const std::string& message, const std::string& hash) {
    std::string result = message + "::hash::" + hash;
    displayStep("STEP 3: Combine Message and Hash", 
                "Message + Hash", 
                "\"" + message + "::hash::" + hash.substr(0, 16) + "...\"");
    return result;
}

std::vector<unsigned char> InteractiveSecureMessage::step4_generateKey() {
    constexpr int keyLength = 64;
    constexpr int iterations = 500000;
    
    std::vector<unsigned char> key(keyLength);
    
    if (PKCS5_PBKDF2_HMAC(password_.c_str(), password_.length(),
                          salt_.data(), salt_.size(),
                          iterations, EVP_sha512(), keyLength, key.data()) != 1) {
        throw std::runtime_error("Key derivation failed");
    }
    
    displayStep("STEP 4: Generate 512-bit Encryption Key (PBKDF2)", 
                "Password: \"" + password_ + "\" + Salt (32 bytes)", 
                "512-bit AES key derived with 500,000 iterations");
    
    // Display the difference between password and key
    std::cout << "\n=== PASSWORD vs KEY EXPLANATION ===\n";
    std::cout << "Password (human input): \"" << password_ << "\"\n";
    std::cout << "Key (cryptographic):    ";
    for (size_t i = 0; i < std::min(key.size(), size_t(16)); ++i) {
        printf("%02x", key[i]);
    }
    std::cout << "... (64 bytes total for AES-512)\n";
    std::cout << "Salt (random):          ";
    for (size_t i = 0; i < std::min(salt_.size(), size_t(16)); ++i) {
        printf("%02x", salt_[i]);
    }
    std::cout << "... (32 bytes total)\n\n";
    
    return key;
}

std::vector<unsigned char> InteractiveSecureMessage::step5_encrypt(const std::string& combined, 
                                                                  const std::vector<unsigned char>& key,
                                                                  const std::vector<unsigned char>& iv) {
    // First encryption with first 32 bytes of key
    EVP_CIPHER_CTX* ctx1 = EVP_CIPHER_CTX_new();
    if (!ctx1) throw std::runtime_error("Failed to create first cipher context");
    
    if (EVP_EncryptInit_ex(ctx1, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx1);
        throw std::runtime_error("Failed to initialize first encryption");
    }
    
    std::vector<unsigned char> firstEncryption(combined.length() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int len = 0, firstLen = 0;
    
    if (EVP_EncryptUpdate(ctx1, firstEncryption.data(), &len,
                         reinterpret_cast<const unsigned char*>(combined.c_str()),
                         combined.length()) != 1) {
        EVP_CIPHER_CTX_free(ctx1);
        throw std::runtime_error("Failed to update first encryption");
    }
    firstLen = len;
    
    if (EVP_EncryptFinal_ex(ctx1, firstEncryption.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx1);
        throw std::runtime_error("Failed to finalize first encryption");
    }
    firstLen += len;
    firstEncryption.resize(firstLen);
    EVP_CIPHER_CTX_free(ctx1);
    
    // Second encryption with last 32 bytes of key (AES-512 equivalent)
    EVP_CIPHER_CTX* ctx2 = EVP_CIPHER_CTX_new();
    if (!ctx2) throw std::runtime_error("Failed to create second cipher context");
    
    if (EVP_EncryptInit_ex(ctx2, EVP_aes_256_cbc(), nullptr, key.data() + 32, iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx2);
        throw std::runtime_error("Failed to initialize second encryption");
    }
    
    std::vector<unsigned char> finalEncryption(firstLen + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int finalLen = 0;
    
    if (EVP_EncryptUpdate(ctx2, finalEncryption.data(), &len,
                         firstEncryption.data(), firstLen) != 1) {
        EVP_CIPHER_CTX_free(ctx2);
        throw std::runtime_error("Failed to update second encryption");
    }
    finalLen = len;
    
    if (EVP_EncryptFinal_ex(ctx2, finalEncryption.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx2);
        throw std::runtime_error("Failed to finalize second encryption");
    }
    finalLen += len;
    finalEncryption.resize(finalLen);
    EVP_CIPHER_CTX_free(ctx2);
    
    displayStep("STEP 5: Encrypt Combined Data (AES-512 Equivalent)", 
                "Combined string + 512-bit key + IV", 
                "Double-encrypted binary data (" + std::to_string(finalLen) + " bytes)");
    return finalEncryption;
}

std::string InteractiveSecureMessage::step6_encodeBase64(const std::vector<unsigned char>& data) {
    int encodedLength = ((data.size() + 2) / 3) * 4;
    std::vector<unsigned char> encoded(encodedLength + 1);
    
    int actualLength = EVP_EncodeBlock(encoded.data(), data.data(), data.size());
    std::string result(reinterpret_cast<char*>(encoded.data()), actualLength);
    
    displayStep("STEP 6: Encode to Base64", 
                "Binary data (" + std::to_string(data.size()) + " bytes)", 
                "Base64 string (" + std::to_string(result.length()) + " characters)");
    return result;
}

std::string InteractiveSecureMessage::step1r_receiveBase64(const std::string& data) {
    displayStep("STEP 1: Receive Base64 String", 
                "None (starting data for receiver)", 
                "Base64 string (" + std::to_string(data.length()) + " characters)");
    return data;
}

std::vector<unsigned char> InteractiveSecureMessage::step2r_decodeBase64(const std::string& encoded) {
    int decodedLength = ((encoded.length() + 3) / 4) * 3;
    std::vector<unsigned char> decoded(decodedLength);
    
    int actualLength = EVP_DecodeBlock(decoded.data(),
                                      reinterpret_cast<const unsigned char*>(encoded.c_str()),
                                      encoded.length());
    
    while (actualLength > 0 && decoded[actualLength - 1] == 0) {
        actualLength--;
    }
    decoded.resize(actualLength);
    
    displayStep("STEP 2: Decode from Base64 to Binary", 
                "Base64 string", 
                "Binary data (" + std::to_string(decoded.size()) + " bytes)");
    return decoded;
}

std::vector<unsigned char> InteractiveSecureMessage::step3r_generateKey() {
    constexpr int keyLength = 64;
    constexpr int iterations = 500000;
    
    std::vector<unsigned char> key(keyLength);
    
    if (PKCS5_PBKDF2_HMAC(password_.c_str(), password_.length(),
                          salt_.data(), salt_.size(),
                          iterations, EVP_sha512(), keyLength, key.data()) != 1) {
        throw std::runtime_error("Key derivation failed");
    }
    
    displayStep("STEP 3: Generate Decryption Key (Same as Encryption)", 
                "Same password + extracted salt", 
                "Identical 512-bit decryption key");
    return key;
}

std::string InteractiveSecureMessage::step4r_decrypt(const std::vector<unsigned char>& ciphertext,
                                                    const std::vector<unsigned char>& key,
                                                    const std::vector<unsigned char>& iv) {
    // First decryption with last 32 bytes of key (reverse order)
    EVP_CIPHER_CTX* ctx1 = EVP_CIPHER_CTX_new();
    if (!ctx1) throw std::runtime_error("Failed to create first cipher context");
    
    if (EVP_DecryptInit_ex(ctx1, EVP_aes_256_cbc(), nullptr, key.data() + 32, iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx1);
        throw std::runtime_error("Failed to initialize first decryption");
    }
    
    std::vector<unsigned char> firstDecryption(ciphertext.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int len = 0, firstLen = 0;
    
    if (EVP_DecryptUpdate(ctx1, firstDecryption.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx1);
        throw std::runtime_error("Failed to update first decryption");
    }
    firstLen = len;
    
    if (EVP_DecryptFinal_ex(ctx1, firstDecryption.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx1);
        throw std::runtime_error("Failed to finalize first decryption");
    }
    firstLen += len;
    firstDecryption.resize(firstLen);
    EVP_CIPHER_CTX_free(ctx1);
    
    // Second decryption with first 32 bytes of key
    EVP_CIPHER_CTX* ctx2 = EVP_CIPHER_CTX_new();
    if (!ctx2) throw std::runtime_error("Failed to create second cipher context");
    
    if (EVP_DecryptInit_ex(ctx2, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx2);
        throw std::runtime_error("Failed to initialize second decryption");
    }
    
    std::vector<unsigned char> finalDecryption(firstLen + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    int finalLen = 0;
    
    if (EVP_DecryptUpdate(ctx2, finalDecryption.data(), &len, firstDecryption.data(), firstLen) != 1) {
        EVP_CIPHER_CTX_free(ctx2);
        throw std::runtime_error("Failed to update second decryption");
    }
    finalLen = len;
    
    if (EVP_DecryptFinal_ex(ctx2, finalDecryption.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx2);
        throw std::runtime_error("Failed to finalize second decryption");
    }
    finalLen += len;
    EVP_CIPHER_CTX_free(ctx2);
    
    std::string result(reinterpret_cast<char*>(finalDecryption.data()), finalLen);
    
    displayStep("STEP 4: Decrypt Binary Data (AES-512 Equivalent)", 
                "Double-encrypted data + key + IV", 
                "\"" + result.substr(0, std::min(50, (int)result.length())) + "...\"");
    return result;
}

std::pair<std::string, std::string> InteractiveSecureMessage::step5r_splitMessageHash(const std::string& combined) {
    const std::string delimiter = "::hash::";
    size_t pos = combined.find(delimiter);
    
    if (pos == std::string::npos) {
        throw std::runtime_error("Invalid message format");
    }
    
    std::string message = combined.substr(0, pos);
    std::string hash = combined.substr(pos + delimiter.length());
    
    displayStep("STEP 5: Split Message and Hash", 
                "Combined string", 
                "Message: \"" + message + "\" + Hash: " + hash.substr(0, 16) + "...");
    return {message, hash};
}

std::string InteractiveSecureMessage::step6r_verifyHash(const std::string& message) {
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512(reinterpret_cast<const unsigned char*>(message.c_str()), message.length(), hash);
    
    std::stringstream ss;
    for (int i = 0; i < SHA512_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    
    std::string result = ss.str();
    displayStep("STEP 6: Verify Integrity (Generate New Hash)", 
                "Received message", 
                "New hash: " + result.substr(0, 32) + "...");
    return result;
}

bool InteractiveSecureMessage::step7r_compareHashes(const std::string& original, const std::string& calculated) {
    bool match = (original == calculated);
    displayStep("STEP 7: Compare Hashes", 
                "Original hash vs New hash", 
                match ? "MATCH [OK] - Message is authentic!" : "MISMATCH [ERROR] - Message tampered!");
    return match;
}

std::vector<unsigned char> InteractiveSecureMessage::generateRandomSalt() {
    std::vector<unsigned char> salt(32);
    if (RAND_bytes(salt.data(), 32) != 1) {
        throw std::runtime_error("Failed to generate salt");
    }
    return salt;
}

bool InteractiveSecureMessage::waitForUserInput() {
    std::cout << "\nPress ENTER to continue to next step (or 'q' + ENTER to quit): ";
    std::string input;
    std::getline(std::cin, input);
    return input != "q" && input != "Q";
}

void InteractiveSecureMessage::displayStep(const std::string& title, const std::string& input, const std::string& output) {
    std::cout << "+-------------------------------------------------------------------+\n";
    std::cout << "| " << title;
    
    // Add padding to make the line 67 characters total
    int padding = 67 - title.length();
    for (int i = 0; i < padding; i++) {
        std::cout << " ";
    }
    std::cout << "|\n";
    std::cout << "+-------------------------------------------------------------------+\n";
    std::cout << "| Input:  " << input;
    
    int inputPadding = 58 - input.length();
    for (int i = 0; i < inputPadding; i++) {
        std::cout << " ";
    }
    std::cout << "|\n";
    std::cout << "| Output: " << output;
    
    int outputPadding = 57 - output.length();
    for (int i = 0; i < outputPadding; i++) {
        std::cout << " ";
    }
    std::cout << "|\n";
    std::cout << "+-------------------------------------------------------------------+\n";
}

}
