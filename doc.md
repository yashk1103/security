[JNI implementation](https://github.com/yashk1103/Secure-Vault/blob/main/doc.md#jni-working-changes-made-to-core-program)

## First Implementation

## **1. PROBLEM UNDERSTANDING**

### **Primary Goal:**

Create an interactive educational cryptographic system that demonstrates secure message encryption/decryption using AES-512 equivalent with step-by-step visualization.

### **Key Requirements:**

- Interactive 7-step encryption process
- Interactive 7-step decryption process
- AES-512 equivalent (dual AES-256) encryption
- PBKDF2 key derivation with 500,000 iterations
- SHA-512 message integrity verification
- User input for custom messages and passwords
- Educational step-by-step display
- OpenSSL implementation

## **2. SYSTEM ARCHITECTURE ANALYSIS**
```
User Input → Encryption Pipeline → Base64 Output → Decryption Pipeline → Verification
     ↓              ↓                    ↓              ↓                ↓
  Message      [7 Steps]           Transmission    [7 Steps]         Integrity
  Password    Interactive           Format        Interactive        Check
```

## **3. FUNCTION PSEUDOCODE DOCUMENTATION**

### **🔧 CONSTRUCTOR**
```
FUNCTION InteractiveSecureMessage(password)
BEGIN
    STORE password in member variable
    GENERATE 32-byte cryptographically secure random salt
    STORE salt in member variable
END
```

### **MAIN ORCHESTRATION FUNCTIONS**

#### **runInteractiveEncryption(message)**
```
FUNCTION runInteractiveEncryption(message)
BEGIN
    PRINT "SENDER SIDE" header
    
    // Step 1: Start with original message
    result1 = CALL step1_startMessage(message)
    WAIT for user input or quit
    
    // Step 2: Generate SHA-512 hash
    result2 = CALL step2_generateHash(result1)
    WAIT for user input or quit
    
    // Step 3: Combine message and hash
    result3 = CALL step3_combineMessageHash(result1, result2)
    WAIT for user input or quit
    
    // Step 4: Generate encryption key
    result4 = CALL step4_generateKey()
    WAIT for user input or quit
    
    // Step 5: Encrypt with dual AES-256
    GENERATE random 16-byte IV
    result5 = CALL step5_encrypt(result3, result4, IV)
    WAIT for user input or quit
    
    // Step 6: Prepare final data and encode
    COMBINE salt + IV + encrypted_data
    final_result = CALL step6_encodeBase64(combined_data)
    
    PRINT final Base64 result
END
```

#### **runInteractiveDecryption(encryptedData)**
```
FUNCTION runInteractiveDecryption(encryptedData)
BEGIN
    PRINT "RECEIVER SIDE" header
    
    // Reverse steps 1-7
    step1_result = CALL step1r_receiveBase64(encryptedData)
    WAIT for user input
    
    step2_result = CALL step2r_decodeBase64(step1_result)
    WAIT for user input
    
    // Extract components
    EXTRACT salt (first 32 bytes)
    EXTRACT IV (next 16 bytes)  
    EXTRACT ciphertext (remaining bytes)
    UPDATE member salt with extracted salt
    
    step3_result = CALL step3r_generateKey()
    WAIT for user input
    
    step4_result = CALL step4r_decrypt(ciphertext, step3_result, IV)
    WAIT for user input
    
    step5_result = CALL step5r_splitMessageHash(step4_result)
    WAIT for user input
    
    step6_result = CALL step6r_verifyHash(step5_result.message)
    WAIT for user input
    
    step7_result = CALL step7r_compareHashes(step5_result.hash, step6_result)
    
    PRINT final verification results
END
```

### **🔐 ENCRYPTION STEP FUNCTIONS**

#### **step1_startMessage(message)**
```
FUNCTION step1_startMessage(message)
BEGIN
    DISPLAY step info: "Start with Original Message"
    INPUT: None (starting data)
    OUTPUT: message string
    RETURN message unchanged
END
```

#### **step2_generateHash(message)**

```
FUNCTION step2_generateHash(message)
BEGIN
    CREATE EVP_MD_CTX context
    INITIALIZE with SHA-512 algorithm
    UPDATE context with message bytes
    FINALIZE to get 64-byte hash
    CONVERT binary hash to hexadecimal string
    DISPLAY step info with truncated hash preview
    CLEANUP context
    RETURN hex_hash_string
END


```


#### **step3_combineMessageHash(message, hash)**


```
FUNCTION step3_combineMessageHash(message, hash)
BEGIN
    CONCATENATE message + "::hash::" + hash
    DISPLAY step info with combined result preview
    RETURN combined_string
END


```


#### **step4_generateKey()**


```

FUNCTION step4_generateKey()
BEGIN
    SET key_length = 64 bytes (512 bits)
    SET iterations = 500,000
    
    CALL PKCS5_PBKDF2_HMAC with:
        - password (member variable)
        - salt (member variable)
        - iterations
        - SHA-512 algorithm
        - output length 64 bytes
    
    DISPLAY step info showing password vs key difference
    PRINT password (human readable)
    PRINT key preview (hex format)
    PRINT salt preview (hex format)
    
    RETURN 64-byte key vector
END

```



#### **step5_encrypt(combined_text, key, iv)**

```

FUNCTION step5_encrypt(combined_text, key, iv)
BEGIN
    // First AES-256 encryption
    CREATE EVP_CIPHER_CTX context1
    INITIALIZE with AES-256-CBC, first 32 bytes of key, IV
    ENCRYPT combined_text
    GET first_encryption_result
    CLEANUP context1
    
    // Second AES-256 encryption (AES-512 equivalent)
    CREATE EVP_CIPHER_CTX context2  
    INITIALIZE with AES-256-CBC, last 32 bytes of key, same IV
    ENCRYPT first_encryption_result
    GET final_encryption_result
    CLEANUP context2
    
    DISPLAY step info with data size
    RETURN final_encrypted_bytes
END

```



#### **step6_encodeBase64(binary_data)**

```

FUNCTION step6_encodeBase64(binary_data)
BEGIN
    CALCULATE required encoded length
    CALL EVP_EncodeBlock to convert binary to Base64
    CONVERT to string
    DISPLAY step info with sizes
    RETURN base64_string
END

```



### **🔓 DECRYPTION STEP FUNCTIONS**

#### **step4r_decrypt(ciphertext, key, iv)**

```

FUNCTION step4r_decrypt(ciphertext, key, iv)
BEGIN
    // First decryption (reverse order - use last 32 bytes first)
    CREATE EVP_CIPHER_CTX context1
    INITIALIZE with AES-256-CBC, last 32 bytes of key, IV
    DECRYPT ciphertext
    GET first_decryption_result
    CLEANUP context1
    
    // Second decryption (use first 32 bytes)
    CREATE EVP_CIPHER_CTX context2
    INITIALIZE with AES-256-CBC, first 32 bytes of key, IV  
    DECRYPT first_decryption_result
    GET final_decryption_result
    CLEANUP context2
    
    CONVERT bytes to string
    DISPLAY step info with preview
    RETURN decrypted_string
END

```



#### **step5r_splitMessageHash(combined_string)**

```

FUNCTION step5r_splitMessageHash(combined_string)
BEGIN
    SET delimiter = "::hash::"
    FIND position of delimiter in string
    IF delimiter not found THEN
        THROW error "Invalid message format"
    
    EXTRACT message = substring before delimiter
    EXTRACT hash = substring after delimiter
    DISPLAY step info with both parts
    RETURN pair(message, hash)
END

```



#### **step6r_verifyHash(message)**

```
FUNCTION step6r_verifyHash(message)
BEGIN
    CALL SHA512 function on message bytes
    CONVERT 64-byte result to hexadecimal string
    DISPLAY step info with new hash preview
    RETURN hex_hash_string
END


```


#### **step7r_compareHashes(original_hash, calculated_hash)**

```
FUNCTION step7r_compareHashes(original_hash, calculated_hash)
BEGIN
    COMPARE strings for exact match
    DISPLAY step info with match result
    RETURN boolean_match_result
END


```


### **🛠️ UTILITY FUNCTIONS**

#### **generateRandomSalt()**

```

FUNCTION generateRandomSalt()
BEGIN
    ALLOCATE 32-byte vector
    CALL RAND_bytes to fill with cryptographically secure random data
    IF generation fails THEN
        THROW error "Failed to generate salt"
    RETURN salt_vector
END

```


----

```


// Cryptographic functions from OpenSSL library
EVP_MD_CTX_new()                    // Create hash context
EVP_MD_CTX_free()                   // Free hash context
EVP_DigestInit_ex()                 // Initialize hashing
EVP_DigestUpdate()                  // Add data to hash
EVP_DigestFinal_ex()                // Finalize hash
EVP_sha512()                        // SHA-512 algorithm
PKCS5_PBKDF2_HMAC()                // Key derivation function
RAND_bytes()                        // Secure random generation
EVP_CIPHER_CTX_new()               // Create cipher context
EVP_CIPHER_CTX_free()              // Free cipher context
EVP_EncryptInit_ex()               // Initialize encryption
EVP_EncryptUpdate()                // Encrypt data chunks
EVP_EncryptFinal_ex()              // Finalize encryption
EVP_DecryptInit_ex()               // Initialize decryption
EVP_DecryptUpdate()                // Decrypt data chunks
EVP_DecryptFinal_ex()              // Finalize decryption
EVP_aes_256_cbc()                  // AES-256-CBC algorithm
EVP_CIPHER_block_size()            // Get cipher block size
EVP_EncodeBlock()                  // Base64 encoding
EVP_DecodeBlock()                  // Base64 decoding
SHA512()                           // Direct SHA-512 hash
```


---

## **4. DATA FLOW ANALYSIS**

```

INPUT: User Message + Password
   ↓
STEP 1: Store message → message
   ↓
STEP 2: SHA-512(message) → hash
   ↓  
STEP 3: message + "::hash::" + hash → combined
   ↓
STEP 4: PBKDF2(password, salt, 500k) → 512-bit key
   ↓
STEP 5: AES256(AES256(combined, key[0:31]), key[32:63]) → encrypted
   ↓
STEP 6: Base64(salt + iv + encrypted) → transmission_string
   ↓
TRANSMISSION → receiver gets transmission_string
   ↓
STEP 1r: Receive transmission_string
   ↓
STEP 2r: Base64_decode → salt + iv + encrypted  
   ↓
STEP 3r: PBKDF2(password, salt, 500k) → same 512-bit key
   ↓
STEP 4r: AES256_decrypt(AES256_decrypt(encrypted, key[32:63]), key[0:31]) → combined
   ↓
STEP 5r: Split combined → message + hash
   ↓
STEP 6r: SHA-512(message) → new_hash
   ↓
STEP 7r: Compare hash == new_hash → integrity_verified

```


---

## **5. SECURITY ANALYSIS OF IMPLEMENTATION**

### **✅ Strong Points:**

- Proper PBKDF2 with 500,000 iterations
- Cryptographically secure random salt and IV
- Dual AES-256 for enhanced security
- SHA-512 for integrity verification
- Proper OpenSSL context management

### **⚠️ Areas for Review:**

- Password displayed in plaintext during step 4
- No input validation for message length
- Same IV used for both AES layers
- Memory not securely wiped after use

## problem with keys

## **1. Class Member Storage Issues (Heap)**

• **Password stored permanently in heap memory**

- `std::string password_;` lives for entire object lifetime
- Never wiped or cleaned up
- Remains in memory until object destruction

• **Salt stored in heap without cleanup**

- `std::vector<unsigned char> salt_;` persists in object
- No secure wiping implemented
- Accessible throughout object lifetime

## **2. Constructor Security Issues**

• **Password copied multiple times**

- [InteractiveSecureMessage(const std::string& password) : password_(password)]
- Creates copy in constructor parameter
- Creates another copy in member initialization
- Original + 2 copies exist simultaneously

## **3. Key Generation Memory Issues**

• **Key created but never wiped**

- `std::vector<unsigned char> key(keyLength);` in [step4_generateKey()]
- Key generated and returned but original never cleaned
- Function stack frame retains key until return

• **Multiple key copies during generation**

- Key created in function
- Key copied for return value
- Both copies exist in memory simultaneously

## **4. Function Call Chain Memory Issues**

• **Keys copied through multiple function calls**

- [step4_result = step4_generateKey();] - Copy 1
- [step5_result = step5_encrypt(..., step4_result, ...);] - Copy 2
- Parameter passing creates additional copies
- All copies remain until function scope ends

• **No cleanup between steps**

- Keys persist across all encryption steps
- Multiple versions in different stack frames
- No explicit wiping until natural scope exit

## **5. Display Security Issues**

• **Password displayed on console**

- `std::cout << "Password (human input): \"" << password_ << "\"\n";`
- Visible on screen and in terminal history
- Can be screenshot or recorded

• **Key bytes displayed in hexadecimal**

- Shows first 16 bytes of cryptographic key
- Partial key exposure reduces security
- Debug information leak

## **6. Main Function Storage Issues**

• **Local variables persist entire execution**

- `std::string password;` in main() lives until program end
- `std::string message;` never cleaned up
- Stack variables retain sensitive data

• **Input handling without masking**

- `std::getline(std::cin, password);` - plain text input
- Password visible while typing
- No hidden input mechanism

## **7. Memory Layout Issues**

### **Stack Memory Problems:**

• Password in main() stack frame • Multiple key copies in function stack frames  
• Message data in various function scopes • No explicit cleanup of stack variables

### **Heap Memory Problems:**

• Password stored in class member (heap allocation) • Salt vector in heap memory • Object lifetime controls memory retention • No destructor cleanup implemented

## **8. Decryption Path Issues**

• **Same password storage problems in receiver**

- `SecureMessaging::InteractiveSecureMessage receiver(password);`
- Creates another permanent copy of password
- Two objects with same password in memory

• **Key regeneration without cleanup**

- [step3r_generateKey()] has same issues as encryption
- Creates key, returns copy, doesn't wipe original
- Decryption keys persist in memory

## **9. No Secure Cleanup Implementation**

• **Missing OPENSSL_cleanse() calls**

- No secure memory wiping anywhere in code
- Standard destructors don't zero memory
- Sensitive data recoverable from memory dumps

• **No explicit variable clearing**

- No `std::fill()` or `memset()` calls
- No `.clear()` followed by `.shrink_to_fit()`
- Variables retain data until overwritten

## **10. Lifetime Management Issues**

• **Object-scoped password retention**

- Password lives as long as crypto object exists
- Multiple crypto objects = multiple password copies
- No way to clear password without destroying object

• **Function-scoped key persistence**

- Keys live until function returns
- Multiple functions = multiple concurrent keys
- Stack unwinding doesn't guarantee secure cleanup

## **Summary of Memory Exposure:**

• **Heap**: Password, salt stored permanently • **Stack**: Multiple key copies, message data, local passwords • **Display**: Console output shows sensitive information • **Duration**: Sensitive data persists much longer than necessary • **Copies**: Multiple simultaneous copies of same sensitive data • **Cleanup**: No secure wiping implemented anywhere


----



## Jni working (changes made to core program)
## **Architecture Flow:**
```
C++ Core Logic (secure_crypto_core.cpp)
           ↓
JNI Bridge (secure_crypto_jni.cpp)
           ↓
Java Main API (src/main/java/) ← Production code
           ↓
Java Tests (src/test/java/) ← Test/demo code
```


# Dual AES-256 Encryption System - Technical Documentation

## Overview

This document explains the complete technical architecture of the Secure Crypto Processor system, which implements dual-layer AES-256 encryption for enhanced security.

##  System Architecture

### Core Components

|Component|File|Purpose|
|---|---|---|
|**User Interface**|secure_crypto.cpp|Interactive menu and user interaction|
|**Core Crypto Logic**|`secure_crypto_core.cpp`|Dual AES-256 implementation|
|**JNI Bridge**|`secure_crypto_jni.cpp`|Java-C++ integration|
|**Java API**|`src/main/java/`|Production Java interface|
|**Test Suite**|`src/test/java/`|Testing and demo applications|
### How Dual Layer Works
```c++
std::string encryptData(const std::string& data, const std::vector<unsigned char>& key) {
    // Split the key into two parts
    std::vector<unsigned char> key1(key.begin(), key.begin() + 32);  // First 32 bytes
    std::vector<unsigned char> key2(key.begin() + 32, key.begin() + 64); // Next 32 bytes
    
    // LAYER 1: Encrypt with first AES-256 key
    std::string layer1_encrypted = aesEncrypt(data, key1);
    
    // LAYER 2: Encrypt the result with second AES-256 key  
    std::string final_encrypted = aesEncrypt(layer1_encrypted, key2);
    
    return final_encrypted;
}
```

### Security Comparison

|Feature|Standard AES-256|Dual AES-256 (This System)|
|---|---|---|
|**Key Length**|256 bits|512 bits (2 × 256)|
|**Security Level**|2^256 operations to break|2^512 operations to break|
|**Quantum Resistance**|Vulnerable to future quantum|Much more quantum-resistant|
|**Attack Surface**|Single encryption layer|Two independent layers|

**Security Benefit**: Even if AES-256 is somehow broken, an attacker would need to break it TWICE with different keys.

### Random Key Generation (RAND_bytes)
```c++
std::vector<unsigned char> generateSecureKey(bool use1488BitKey) {
    size_t keySize = use1488BitKey ? 93 : 64;  // 1488-bit or 512-bit
    std::vector<unsigned char> key(keySize);
    
    // RAND_bytes generates cryptographically secure random numbers
    if (RAND_bytes(key.data(), keySize) != 1) {
        throw std::runtime_error("Failed to generate secure random key");
    }
    
    return key;
}
```

**What is RAND_bytes?**

- OpenSSL's cryptographically secure random number generator
- Uses hardware entropy sources (mouse movements, keyboard timings, etc.)
- NOT like regular `rand()` - unpredictable even to attackers

### Hex Encoding Usage

**Where Hex Encoding is Used:**

1. **Key Display**: Binary keys converted to readable hex format
2. **Key Input**: Users enter keys in hex format
3. **Internal Conversion**: Hex strings converted back to binary for crypto operations

```c++
// Convert binary key to hex for display
std::string hexKey = toHex(binaryKey);

// Convert user hex input back to binary
std::vector<unsigned char> binaryKey = hexToBytes(hexKey);
```

**Why Hex?** Keys are binary data (random bytes), but humans need readable text format:

- Binary: `[0x1A, 0x2B, 0x3C]` → Hex: `"1A2B3C"`

### 3. Base64 Encoding

Used for encrypted data to ensure safe transmission and storage:

- Converts binary encrypted data to text format
- Safe for email, text files, databases
- Standard encoding for data exchange

## Complete flow
# encryption side
```
1. User Selects Encryption
   ↓
2. Enter Message
   ↓
3. Select Key Size (512-bit or 1488-bit)
   ↓
4. RAND_bytes Generates Random Key
   ↓
5. Split Key: Key1 + Key2
   ↓
6. Layer 1: AES-256 Encrypt with Key1
   ↓
7. Layer 2: AES-256 Encrypt with Key2
   ↓
8. Base64 Encode Result
   ↓
9. Hex Encode Key
   ↓
10. Display: Encrypted Data + Hex Key
    ↓
11. Secure Memory Wipe
```

## Decryption side
```
1. User Selects Decryption
   ↓
2. Enter Base64 Encrypted Data
   ↓
3. Enter Hex Key
   ↓
4. Hex Decode Key to Binary
   ↓
5. Base64 Decode Encrypted Data
   ↓
6. Split Key: Key1 + Key2
   ↓
7. Layer 1: AES-256 Decrypt with Key2 (reverse order)
   ↓
8. Layer 2: AES-256 Decrypt with Key1
   ↓
9. Display Original Message
   ↓
10. Secure Memory Wipe
```

## Security Arch
```
Random Entropy → 512-bit Key → Split → AES-256(AES-256(data)) → Base64 → Display
                                ↓
                            Immediate Wipe
```

**When hashing WOULD be needed**:

- Network transmission (verify data not corrupted)
- Long-term file storage (verify file integrity)
- Multi-user systems (verify sender identity)

## **Key Lengths Generated by RAND_bytes:**

|Option|Total Bytes|Total Bits|Purpose|
|---|---|---|---|
|**512-bit mode**|64 bytes|512 bits|Dual AES-256 (256 + 256)|
|**1488-bit mode**|93 bytes|744 bits|Enhanced security|

---

## **Key Splitting Process:**

### **For 512-bit Keys (64 bytes total):**
```c++
// Split into two AES-256 keys
std::vector<unsigned char> key1(key.begin(), key.begin() + 32);  // First 32 bytes (256 bits)
std::vector<unsigned char> key2(key.begin() + 32, key.begin() + 64); // Next 32 bytes (256 bits)
```

**Breakdown:**

- **Total generated**: 64 bytes (512 bits)
- **Key1**: Bytes 0-31 = 32 bytes = 256 bits
- **Key2**: Bytes 32-63 = 32 bytes = 256 bits
- **Result**: Two complete AES-256 keys

### **For 1488-bit Keys (93 bytes total):**
```c++
// Enhanced splitting for larger keys
std::vector<unsigned char> key1(key.begin(), key.begin() + 32);  // First 32 bytes (256 bits)
std::vector<unsigned char> key2(key.begin() + 32, key.begin() + 64); // Next 32 bytes (256 bits)
// Remaining 29 bytes used for additional entropy
```

**Breakdown:**

- **Total generated**: 93 bytes (744 bits)
- **Key1**: Bytes 0-31 = 32 bytes = 256 bits (AES-256)
- **Key2**: Bytes 32-63 = 32 bytes = 256 bits (AES-256)
- **Extra entropy**: Bytes 64-92 = 29 bytes = 232 bits (additional security)

## **Visual Representation:**

### **512-bit Key Split:**

```
RAND_bytes generates: [64 bytes total]
│────────── 32 bytes ──────────│────────── 32 bytes ──────────│
│         Key1 (AES-256)       │         Key2 (AES-256)       │
│        256 bits              │        256 bits              │
└──────────────────────────────┴──────────────────────────────┘
```

### **1488-bit Key Split:**

```
RAND_bytes generates: [93 bytes total]
│────── 32 bytes ──────│────── 32 bytes ──────│──── 29 bytes ────│
│    Key1 (AES-256)    │    Key2 (AES-256)    │  Extra Entropy   │
│     256 bits         │     256 bits         │    232 bits      │
└─────────────────────┴─────────────────────┴─────────────────┘
```

## **Hex Display Lengths:**

When displayed in hex format (your Java app shows these):

|Key Type|Bytes Generated|Hex Characters|Display Example|
|---|---|---|---|
|**512-bit**|64 bytes|128 hex chars|`1a2b3c...` (128 chars)|
|**1488-bit**|93 bytes|186 hex chars|`1a2b3c...` (186 chars)|

**Formula**: Hex characters = Bytes × 2 (each byte = 2 hex digits)

## **Security Analysis:**

### **512-bit Mode:**

- **Effective security**: 512 bits total entropy
- **AES layers**: Two independent 256-bit keys
- **Attack complexity**: 2^256 × 2^256 = 2^512 operations

### **1488-bit Mode:**

- **Effective security**: 744 bits total entropy
- **AES layers**: Two independent 256-bit keys + extra randomness
- **Attack complexity**: Enhanced beyond standard dual AES-256

## **Key Usage Flow:**
```
1. RAND_bytes → Generate 64 or 93 random bytes
2. Split → Extract Key1 (32 bytes) and Key2 (32 bytes)
3. Encrypt → AES-256(AES-256(data, Key1), Key2)
4. Display → Convert full key to hex (128 or 186 characters)
5. Wipe → OPENSSL_cleanse all key data
```

## **Important Notes:**

• **RAND_bytes quality**: Uses system entropy (mouse, keyboard, hardware) • **Cryptographic grade**: Suitable for production cryptographic applications • **No predictable patterns**: Each byte is truly random • **Platform independent**: Works consistently across different systems • **OpenSSL standard**: Industry-standard random number generation

---------
#  Function-by-Function Explanation of Secure Crypto System

## **Main Program Flow secure_crypto.cpp**

###   Main Function Flow:
```c++
int main() {
    SecureCryptoProcessor crypto;  // Initialize crypto processor
    
    do {
        displayMenu();             // Show options
        choice = getChoice();      // Get user input
        
        switch (choice) {
            case 1: encryptMessage(crypto, false);  // 512-bit
            case 2: encryptMessage(crypto, true);   // 1488-bit
            case 3: decryptMessage(crypto);         // Decrypt
            case 4: displaySystemInfo();           // Info
            case 5: exit;                          // Quit
        }
    } while (choice != 5);
}
```
---

##  User Interface Functions ([secure_crypto.cpp])

### **1. [displayMenu()]**

```c++
void displayMenu() {
    // Simply prints the menu options
    std::cout << "1. Encrypt Message (512-bit key)" << std::endl;
    std::cout << "2. Encrypt Message (1488-bit key)" << std::endl;
    // ... etc
}
```

**Purpose**: Display user options

### **2. [getChoice()]**

```c++
int getChoice() {
    while (!(std::cin >> choice) || choice < 1 || choice > 5) {
        // Keep asking until valid input (1-5)
        std::cin.clear();  // Clear error flags
    }
    return choice;
}
```

**Purpose**: Get valid menu choice from user

### **3. [getMultilineInput()]**

```c++
std::string getMultilineInput(const std::string& prompt) {
    // Allow user to enter multiple lines
    // Stop when user presses Enter twice (empty line)
    while (std::getline(std::cin, line)) {
        if (line.empty()) {
            emptyLines++;
            if (emptyLines >= 2) break;  // Two empty lines = done
        }
    }
    return result;
}
```


**Purpose**: Get multi-line message input from user

### **4. [encryptMessage()]**

```c++
void encryptMessage(SecureCryptoProcessor& crypto, bool use1488BitKey) {
    // 1. Get message from user
    std::string message = getMultilineInput("Enter your message:");
    
    // 2. Call core crypto function
    auto result = crypto.encryptMessage(message, use1488BitKey);
    
    // 3. Display results
    std::cout << "Encrypted Data: " << result.first << std::endl;   // Base64
    std::cout << "Key: " << result.second << std::endl;             // Hex
}
```
 

**Purpose**: Handle user encryption workflow

### **5. [decryptMessage()]**

```c++
void decryptMessage(SecureCryptoProcessor& crypto) {
    // 1. Get encrypted data from user
    std::string encryptedData = getMultilineInput("Enter encrypted data:");
    
    // 2. Get key from user
    std::getline(std::cin, key);
    
    // 3. Call core crypto function
    std::string result = crypto.decryptMessage(encryptedData, key);
    
    // 4. Display decrypted message
    std::cout << "Decrypted: " << result << std::endl;
}
```


**Purpose**: Handle user decryption workflow

---

## ** Core Crypto Functions ([secure_crypto_core.cpp])**

### **6. Constructor: [SecureCryptoProcessor()]**

```c++
SecureCryptoProcessor::SecureCryptoProcessor() {
    // Check if OpenSSL random generator is ready
    if (!RAND_status()) {
        throw std::runtime_error("OpenSSL RNG not seeded");
    }
}
```


**Purpose**: Initialize OpenSSL and verify it's ready

### **7. [encryptMessage()]- Main Encryption**

```c++
std::pair<std::string, std::string> encryptMessage(const std::string& message, bool use1488BitKey) {
    // Step 1: Generate random key
    auto key = generateSecureKey(use1488BitKey);
    
    // Step 2: Encrypt with dual AES-256
    auto encryptedData = performEncryption(message, key);
    
    // Step 3: Convert to user-friendly formats
    std::string base64Data = toBase64(encryptedData);  // For transmission
    std::string hexKey = toHex(key);                   // For display
    
    // Step 4: Clean up sensitive data
    secureWipe(key);
    secureWipe(encryptedData);
    
    return {base64Data, hexKey};
}
```


**Flow**: Generate Key → Encrypt → Convert → Cleanup → Return

### **8. [decryptMessage()] - Main Decryption**

```c++
std::string decryptMessage(const std::string& encryptedData, const std::string& keyHex) {
    // Step 1: Validate key format
    if (!isValidHexKey(keyHex)) {
        addRandomDelay();  // Anti-timing attack
        throw std::runtime_error("Invalid key");
    }
    
    // Step 2: Convert formats back to binary
    auto key = fromHex(keyHex);                    // Hex → Binary
    auto binaryData = fromBase64(encryptedData);   // Base64 → Binary
    
    // Step 3: Decrypt with dual AES-256
    std::string result = performDecryption(binaryData, key);
    
    // Step 4: Cleanup
    secureWipe(key);
    secureWipe(binaryData);
    
    return result;
}
```


**Flow**: Validate → Convert → Decrypt → Cleanup → Return

---

## ** Key Generation Functions**

### **9. [generateSecureKey()]**

```c++
std::vector<unsigned char> generateSecureKey(bool use1488Bit) {
    size_t keySize = use1488Bit ? 93 : 64;  // Choose size
    std::vector<unsigned char> key(keySize);
    
    // Generate cryptographically secure random bytes
    if (RAND_bytes(key.data(), keySize) != 1) {
        secureWipe(key);
        throw std::runtime_error("Random generation failed");
    }
    
    return key;
}
```

**Purpose**: Generate random key using OpenSSL's secure random generator

- **512-bit**: 64 bytes
- **1488-bit**: 93 bytes

---

## **🔒 Dual Encryption Functions**

### **10. [performEncryption()] - Core Encryption Logic**

```c++
std::vector<unsigned char> performEncryption(const std::string& plaintext, const std::vector<unsigned char>& key) {
    // Step 1: Generate random IV (Initialization Vector)
    std::vector<unsigned char> iv(16);
    RAND_bytes(iv.data(), 16);
    
    // Step 2: FIRST AES-256 LAYER
    EVP_CIPHER_CTX* ctx1 = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx1, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());  // Use first 32 bytes
    
    // Encrypt plaintext → buffer1
    EVP_EncryptUpdate(ctx1, buffer1.data(), &len1, plaintext.data(), plaintext.length());
    EVP_EncryptFinal_ex(ctx1, buffer1.data() + len1, &finalLen1);
    
    // Step 3: SECOND AES-256 LAYER
    EVP_CIPHER_CTX* ctx2 = EVP_CIPHER_CTX_new();
    size_t secondKeyOffset = 32;  // Use bytes 32-63 of key
    EVP_EncryptInit_ex(ctx2, EVP_aes_256_cbc(), nullptr, key.data() + secondKeyOffset, iv.data());
    
    // Encrypt buffer1 → buffer2
    EVP_EncryptUpdate(ctx2, buffer2.data(), &len2, buffer1.data(), buffer1.size());
    EVP_EncryptFinal_ex(ctx2, buffer2.data() + len2, &finalLen2);
    
    // Step 4: Combine IV + encrypted data
    std::vector<unsigned char> result;
    result.insert(result.end(), iv.begin(), iv.end());        // First 16 bytes: IV
    result.insert(result.end(), buffer2.begin(), buffer2.end()); // Rest: encrypted data
    
    return result;
}
```


**Flow**: Generate IV → AES-256(plaintext) → AES-256(result) → Combine IV+data

### **11. [performDecryption()]- Core Decryption Logic**

```c++
std::string performDecryption(const std::vector<unsigned char>& cipherdata, const std::vector<unsigned char>& key) {
    // Step 1: Extract IV and encrypted data
    std::vector<unsigned char> iv(cipherdata.begin(), cipherdata.begin() + 16);  // First 16 bytes
    std::vector<unsigned char> encrypted(cipherdata.begin() + 16, cipherdata.end()); // Rest
    
    // Step 2: FIRST DECRYPTION LAYER (reverse order - second key first)
    size_t secondKeyOffset = 32;
    EVP_DecryptInit_ex(ctx1, EVP_aes_256_cbc(), nullptr, key.data() + secondKeyOffset, iv.data());
    
    // Decrypt encrypted → buffer1
    EVP_DecryptUpdate(ctx1, buffer1.data(), &len1, encrypted.data(), encrypted.size());
    EVP_DecryptFinal_ex(ctx1, buffer1.data() + len1, &finalLen1);
    
    // Step 3: SECOND DECRYPTION LAYER (first key)
    EVP_DecryptInit_ex(ctx2, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());  // First 32 bytes
    
    // Decrypt buffer1 → buffer2 (original plaintext)
    EVP_DecryptUpdate(ctx2, buffer2.data(), &len2, buffer1.data(), buffer1.size());
    EVP_DecryptFinal_ex(ctx2, buffer2.data() + len2, &finalLen2);
    
    // Step 4: Convert to string
    std::string result(buffer2.begin(), buffer2.end());
    
    return result;
}
```


**Flow**: Extract IV+data → AES-256 decrypt(layer2) → AES-256 decrypt(layer1) → Plaintext


---


#  IV Usage in Your Dual AES-256 System
## **The IV is Generated ONCE and Used TWICE**

Looking at your `performEncryption()` function:

```c++
std::vector<unsigned char> performEncryption(const std::string& plaintext, const std::vector<unsigned char>& key) {
    // Step 1: Generate IV ONCE
    std::vector<unsigned char> iv(16);
    RAND_bytes(iv.data(), 16);  // ← IV generated here
    
    // Step 2: FIRST AES-256 layer (uses the IV)
    EVP_EncryptInit_ex(ctx1, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());  // ← IV used here
    
    // Step 3: SECOND AES-256 layer (uses SAME IV)
    EVP_EncryptInit_ex(ctx2, EVP_aes_256_cbc(), nullptr, key.data() + 32, iv.data());  // ← SAME IV used here
    
    // Step 4: Combine IV + final encrypted data
    std::vector<unsigned char> result;
    result.insert(result.end(), iv.begin(), iv.end());        // ← IV stored here for later decryption
    result.insert(result.end(), buffer2.begin(), buffer2.end()); // Final encrypted data
    
    return result;
}
```

## **Detailed IV Flow:**

### **Step 1: IV Generation**

```c++
std::vector<unsigned char> iv(16);  // Create 16-byte IV
RAND_bytes(iv.data(), 16);          // Fill with random bytes
// IV = [0x1A, 0x2B, 0x3C, 0x4D, ...]
```


### **Step 2: First AES Layer (IV Used)**

```c++
// CBC Mode: First block = Plaintext ⊕ IV
EVP_EncryptInit_ex(ctx1, EVP_aes_256_cbc(), nullptr, key1, iv.data());
//                                                          ↑ IV used for CBC chaining

Plaintext Block 1 ⊕ IV → AES_Encrypt(Key1) → Intermediate Block 1
Plaintext Block 2 ⊕ Intermediate Block 1 → AES_Encrypt(Key1) → Intermediate Block 2
// etc...
```

### **Step 3: Second AES Layer (SAME IV Used)**

```c++
// CBC Mode: Use SAME IV for second layer
EVP_EncryptInit_ex(ctx2, EVP_aes_256_cbc(), nullptr, key2, iv.data());
//                                                          ↑ SAME IV used again

Intermediate Block 1 ⊕ IV → AES_Encrypt(Key2) → Final Block 1
Intermediate Block 2 ⊕ Final Block 1 → AES_Encrypt(Key2) → Final Block 2
// etc...
```

### **Step 4: IV Storage (For Decryption)**

```c++
// Prepend IV to the final encrypted data
result = [IV] + [Final Encrypted Data]
//       ↑ IV stored so decryption can use it later
```

----

## **IV Storage Location: RAM (Runtime Memory)**

The IV is stored **in RAM (runtime memory)**, not in any permanent storage. Here's exactly where:

## **🔍 Memory Storage Analysis:**

### **During Encryption**
```c++
std::vector<unsigned char> result;
result.insert(result.end(), iv.begin(), iv.end());        // ← IV copied to result vector (RAM)
result.insert(result.end(), buffer2.begin(), buffer2.end()); // Encrypted data appended

return result;  // ← Entire result (IV + encrypted data) returned in RAM
```
### **Memory Layout:**
```
RAM Memory:
┌─────────────────────────────────────────────────────────┐
│  result vector in RAM                                   │
│  ┌─── 16 bytes ───┐┌──── Variable length ────┐         │
│  │      IV        ││   Encrypted Data        │         │
│  │ [1A 2B 3C ...] ││ [Encrypted bytes...]    │         │
│  └────────────────┘└─────────────────────────┘         │
└─────────────────────────────────────────────────────────┘
```

## **Exact Storage Locations:**

### **1. Function Return (RAM):**

```c++
auto result = crypto.encryptMessage(message, use1488BitKey);
//   ↑ result.first = Base64 string containing IV + encrypted data (in RAM)
//   ↑ result.second = Hex key string (in RAM)

```


### **2. Display to User (RAM → Screen):**

```c++
std::cout << "Encrypted Data: " << result.first << std::endl;
//                                 ↑ Base64 string in RAM displayed on screen

```


### **3. User Input Storage (RAM):**

```c++
std::string encryptedData;
std::getline(std::cin, encryptedData);  // ← User types, stored in RAM string
//           ↑ Contains IV + encrypted data in Base64 format

```

## ** Complete IV Journey Through Memory:**

```c++
1. Generation (RAM):
   std::vector<unsigned char> iv(16);  ← Allocated in RAM
   RAND_bytes(iv.data(), 16);         ← Random bytes written to RAM

2. Encryption Use (RAM):
   EVP_EncryptInit_ex(..., iv.data()); ← Read from RAM for AES operations
   
3. Result Combination (RAM):
   result.insert(..., iv.begin(), iv.end()); ← IV copied to result vector in RAM

4. Base64 Conversion (RAM):
   std::string base64 = toBase64(result); ← New string created in RAM

5. Display (RAM → Screen):
   std::cout << base64; ← Read from RAM, displayed on screen

6. User Storage (External):
   User copies from screen → Text file/email/notes (outside your program)

7. User Input (External → RAM):
   User types → std::string encryptedData ← Back into RAM

8. Decryption Extraction (RAM):
   std::vector<unsigned char> iv(data.begin(), data.begin() + 16); ← IV extracted back to RAM

```


## ** Storage Types Explained:**

### ** What IS Used (RAM/Runtime):**

- **Stack memory**: Local variables like `std::vector<unsigned char> iv(16)`
- **Heap memory**: Dynamic allocations within vectors/strings
- **CPU registers**: Temporary during calculations
- **Screen buffer**: When displayed to user

### **What is NOT Used (Permanent Storage):**

- **Hard disk**: No files written
- **Database**: No database storage
- **Registry**: No Windows registry entries
- **Network**: No network transmission (unless user does it manually)

## ** IV Lifetime in Memory:**

### **Encryption Function Scope:**

```c++
std::pair<std::string, std::string> encryptMessage(...) {
    std::vector<unsigned char> iv(16);  // ← Created in RAM (stack)
    RAND_bytes(iv.data(), 16);          // ← Filled in RAM
    
    // ... use iv for encryption ...
    
    std::string base64Data = toBase64(result); // ← IV now part of base64 string (heap)
    
    secureWipe(iv);  // ← Original IV vector wiped from RAM
    
    return {base64Data, hexKey}; // ← IV still exists inside base64Data string
    
    // ← iv vector destroyed here, but IV bytes live on in base64Data
}
```



### **Memory Timeline:**

```c++
Time 1: IV generated in RAM (stack allocation)
Time 2: IV used for encryption (still in same RAM location)
Time 3: IV copied to result vector (now in heap RAM)
Time 4: result converted to Base64 string (new heap RAM allocation)
Time 5: Original IV vector wiped (stack RAM cleared)
Time 6: Function returns (stack destroyed, but heap Base64 string continues)
Time 7: Base64 string displayed to user (RAM → screen)
Time 8: Program ends (all RAM released by OS)

```



## ** Security Implications:**

### **RAM Storage Risks:**

- **Memory dumps**: IV visible in crash dumps
- **Swap files**: IV might be written to disk if RAM is swapped
- **Debugger access**: IV visible to debuggers
- **Process memory scanning**: Malware could scan RAM

### **Temporary vs Permanent:**

```c++
RAM Storage (Your System):
├── Temporary (while program runs)
├── Cleared when program exits
├── Vulnerable to memory attacks
└── Not persistent across reboots

File Storage (Not Used):
├── Permanent until deleted
├── Survives program exit/reboot
├── Vulnerable to disk forensics
└── Can be encrypted at rest

```


## ** Summary:**

**The IV is stored in RAM (runtime memory) only:**

• **Generated**: In RAM during encryption • **Used**: From RAM for AES operations  
• **Combined**: With encrypted data in RAM • **Displayed**: From RAM to screen • **Input**: From user back to RAM • **Extracted**: In RAM during decryption • **Lifetime**: Exists only while program runs • **Cleanup**: Automatically freed when program exits

**No permanent storage (files, database, disk) is used for the IV - it exists only in volatile memory during program execution.**

-----

## **Visual Representation:**

```c++
Generated IV: [1A 2B 3C 4D ... ] (16 bytes)
                ↓         ↓
           Used Here  Used Here
                ↓         ↓
Plaintext → AES-256-CBC → AES-256-CBC → Final Encrypted
           (Key1, IV)   (Key2, SAME IV)
                                  ↓
                            [IV + Encrypted Data]
                             ↑ IV stored for decryption
```



## **Why Store the IV at the End?**

### **Problem Without Stored IV:**

```c++
Encryption: Generate IV → Use for both layers → Discard IV
Decryption: ??? → How do we decrypt without the IV?
```


### **Solution - Store IV with Data:**

```c++
Encryption: Generate IV → Use for both layers → Store IV + encrypted data
Decryption: Extract IV → Use same IV for both decrypt layers → Get plaintext
```


## **Decryption Process (IV Extraction):**

```c++
std::string performDecryption(const std::vector<unsigned char>& cipherdata, const std::vector<unsigned char>& key) {
    // Step 1: Extract the stored IV
    std::vector<unsigned char> iv(cipherdata.begin(), cipherdata.begin() + 16);  // First 16 bytes
    std::vector<unsigned char> encrypted(cipherdata.begin() + 16, cipherdata.end()); // Rest is encrypted data
    
    // Step 2: Reverse Layer 2 (Key2 with extracted IV)
    EVP_DecryptInit_ex(ctx1, EVP_aes_256_cbc(), nullptr, key.data() + 32, iv.data());
    //                                                                     ↑ Use extracted IV
    
    // Step 3: Reverse Layer 1 (Key1 with same IV)
    EVP_DecryptInit_ex(ctx2, EVP_aes_256_cbc(), nullptr, key.data(), iv.data());
    //                                                               ↑ Use same extracted IV
}
```


## **Data Structure:**

### **What Gets Stored:**

```
Final Output = [IV (16 bytes)] + [Double-Encrypted Data (variable length)]
               └─ Not secret ─┘   └──── Secret encrypted content ────┘
```


### **Example:**

```c++
Original Message: "Hello World"
Generated IV: [1A 2B 3C 4D E5 F6 ...]
Key1: [First 32 bytes of your key]
Key2: [Next 32 bytes of your key]

After Encryption:
Result = [1A 2B 3C 4D E5 F6 ...] + [Encrypted Data]
         └─── Same IV used twice ──┘   └─ Final output ─┘
```


## **Key Points:**

• **IV Generated Once**: `RAND_bytes(iv.data(), 16)` - happens once • **IV Used Twice**: Both AES layers use the same IV for consistency  
• **IV Stored Once**: Prepended to final result for decryption access • **IV Not Secret**: Can be stored in plain text (it's the randomness that matters) • **Decryption Needs IV**: Must extract and use the same IV to reverse both layers

## **Why Use Same IV for Both Layers?**

**Consistency Requirement:**

- Layer 1 encrypts with IV
- Layer 2 encrypts the result of Layer 1 (with same IV)
- To decrypt: Must reverse Layer 2 first, then Layer 1
- Both reversals need the exact same IV that was used for encryption

**If different IVs were used:**

```c++
Encrypt: Plaintext → AES(Key1, IV1) → AES(Key2, IV2) → Final
Decrypt: Final → AES⁻¹(Key2, IV2) → AES⁻¹(Key1, IV1) → Plaintext
                 ↑ Need IV2        ↑ Need IV1
                 Would need to store TWO IVs!
```


**our approach (same IV):**

```c++
Encrypt: Plaintext → AES(Key1, IV) → AES(Key2, IV) → Final  
Decrypt: Final → AES⁻¹(Key2, IV) → AES⁻¹(Key1, IV) → Plaintext
                ↑ Same IV        ↑ Same IV
                Only need to store ONE IV!
```



**So the IV is generated once, used twice (for both encryption layers), and stored once (for decryption access).**


---


## **🔄 Format Conversion Functions**

### **12. [toBase64()]/ [fromBase64()]**

```c++
std::string toBase64(const std::vector<unsigned char>& data) {
    // Convert binary data to Base64 text using OpenSSL
    EVP_EncodeBlock(encoded.data(), data.data(), data.size());
    return std::string(encoded.begin(), encoded.end());
}

std::vector<unsigned char> fromBase64(const std::string& encoded) {
    // Convert Base64 text back to binary using OpenSSL
    EVP_DecodeBlock(decoded.data(), encoded.c_str(), encoded.length());
    return decoded;
}
```


**Purpose**: Convert binary ↔ Base64 for safe transmission

### **13. [toHex()]/ [fromHex()]**

```c++
std::string toHex(const std::vector<unsigned char>& data) {
    std::ostringstream oss;
    for (unsigned char byte : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return oss.str();
}

std::vector<unsigned char> fromHex(const std::string& hex) {
    // Convert "1A2B3C" → [0x1A, 0x2B, 0x3C]
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = std::stoul(byteString, nullptr, 16);
        result.push_back(byte);
    }
    return result;
}
```


**Purpose**: Convert binary ↔ Hex for human-readable keys

---

## ** Security Functions**

### **14. [secureWipe()]**

```c++
void secureWipe(std::vector<unsigned char>& data) {
#ifdef _WIN32
    SecureZeroMemory(data.data(), data.size());  // Windows secure wipe
#else
    explicit_bzero(data.data(), data.size());    // Unix secure wipe
#endif
    data.clear();
    data.shrink_to_fit();  // Release memory
}
```


**Purpose**: Securely erase sensitive data from memory

### **15. [addRandomDelay()]**

```c++
void addRandomDelay() {
    std::uniform_int_distribution<> dis(50, 150);  // Random 50-150ms
    std::this_thread::sleep_for(std::chrono::milliseconds(dis(gen)));
}
```


**Purpose**: Prevent timing attacks during error handling

### **16. Key Validation Functions**

```c++
bool isValidHexKey(const std::string& hex) {
    return isValid512BitKey(hex) || isValid1488BitKey(hex);
}

bool isValid512BitKey(const std::string& hex) {
    return hex.length() == 128 && allValidHexChars(hex);  // 64 bytes = 128 hex chars
}

bool isValid1488BitKey(const std::string& hex) {
    return hex.length() == 186 && allValidHexChars(hex);  // 93 bytes = 186 hex chars
}
```


**Purpose**: Validate key format before attempting decryption

---

## ** Complete Function Call Flow**

### **Encryption Path:**

```c++
main() → encryptMessage() → crypto.encryptMessage() → generateSecureKey() → performEncryption() → toBase64() + toHex() → secureWipe()
```


### **Decryption Path:**

```c++
main() → decryptMessage() → crypto.decryptMessage() → isValidHexKey() → fromHex() + fromBase64() → performDecryption() → secureWipe()
```

### **Data Flow:**

```c++
User Input → String → Binary → Encrypted Binary → Base64 String → Display
Display → Base64 String → Binary → Decrypted Binary → String → User Output
```

-
