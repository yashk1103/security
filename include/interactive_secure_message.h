#pragma once

#include <string>
#include <vector>
#include <utility>

namespace SecureMessaging {

class InteractiveSecureMessage {
public:
    explicit InteractiveSecureMessage(const std::string& password);
    ~InteractiveSecureMessage() = default;

    void runInteractiveEncryption(const std::string& message);
    void runInteractiveDecryption(const std::string& encryptedData);

private:
    std::string password_;
    std::vector<unsigned char> salt_;
    
    std::string step1_startMessage(const std::string& message);
    std::string step2_generateHash(const std::string& message);
    std::string step3_combineMessageHash(const std::string& message, const std::string& hash);
    std::vector<unsigned char> step4_generateKey();
    std::vector<unsigned char> step5_encrypt(const std::string& combined, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv);
    std::string step6_encodeBase64(const std::vector<unsigned char>& data);
    
    std::string step1r_receiveBase64(const std::string& data);
    std::vector<unsigned char> step2r_decodeBase64(const std::string& encoded);
    std::vector<unsigned char> step3r_generateKey();
    std::string step4r_decrypt(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv);
    std::pair<std::string, std::string> step5r_splitMessageHash(const std::string& combined);
    std::string step6r_verifyHash(const std::string& message);
    bool step7r_compareHashes(const std::string& original, const std::string& calculated);
    
    std::vector<unsigned char> generateRandomSalt();
    bool waitForUserInput();
    void displayStep(const std::string& title, const std::string& input, const std::string& output);
};

}
