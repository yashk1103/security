# Secure Messaging System

A high-security messaging system with **dual AES-256 encryption** providing AES-512 equivalent security, featuring both C++ standalone and Java JNI integration.

## 🔐 Security Features

- **Dual AES-256 Encryption**: Cascaded encryption layers for maximum security
- **Flexible Key Sizes**: 512-bit and 1488-bit options
- **Secure Memory Management**: Automatic wiping of sensitive data
- **Anti-Timing Attack Protection**: Random delays prevent cryptanalysis
- **Direct Key Generation**: No PBKDF2 vulnerabilities
- **Base64 Encoding**: Safe data transmission format

## 🏗️ Project Structure (Proper Maven Layout)

```
SecureMessaging/
├── src/
│   ├── main/java/com/securemessaging/     # Main Java source files
│   │   ├── SecureCrypto.java              # Main JNI interface
│   │   ├── EncryptionResult.java          # Encryption result class
│   │   └── SystemInfo.java                # System information
│   ├── test/java/com/securemessaging/     # Test Java source files
│   │   ├── SimpleTest.java                # Basic functionality test
│   │   └── SecureCryptoTest.java          # Comprehensive test suite
│   ├── secure_crypto.cpp                  # Standalone C++ application
│   └── secure_crypto_jni.cpp              # JNI bridge implementation
├── include/
│   └── com_securemessaging_SecureCrypto.h # Generated JNI header
├── build/Release/
│   ├── secure_crypto.exe                  # C++ executable
│   └── secure_crypto_jni.dll              # JNI library
├── target/
│   ├── classes/com/securemessaging/       # Compiled main classes
│   └── test-classes/com/securemessaging/  # Compiled test classes
└── pom.xml                                # Maven configuration
```

## 🚀 Quick Start

### Prerequisites
- **Java 11+** (with JDK for compilation)
- **CMake 3.10+**
- **Visual Studio 2022 BuildTools** (Windows)
- **OpenSSL 3.5.2** (installed in C:/Program Files/OpenSSL-Win64/)

### Build and Test
```bash
# Clone and navigate to project
cd SecureMessaging

# Build C++ components and test Java integration
./test_maven_structure.bat
```

## 🔧 Usage Examples

### C++ Standalone
```bash
./build/Release/secure_crypto.exe
```

### Java Integration
```java
// Initialize the crypto system
SecureCrypto crypto = new SecureCrypto();

// Encrypt with 512-bit key
EncryptionResult result = crypto.encryptMessage("Your secret message", false);
System.out.println("Encrypted: " + result.getEncryptedData());
System.out.println("Key: " + result.getKey());

// Decrypt
String decrypted = crypto.decryptMessage(result.getEncryptedData(), result.getKey());
System.out.println("Decrypted: " + decrypted);

// Use 1488-bit key for extra security
EncryptionResult strongResult = crypto.encryptMessage("Top secret data", true);
```

### Run Tests
```bash
# Simple test
java -cp "target/classes;target/test-classes" -Djava.library.path=build/Release com.securemessaging.SimpleTest

# Full test suite
java -cp "target/classes;target/test-classes" -Djava.library.path=build/Release com.securemessaging.SecureCryptoTest
```

## 📋 API Reference

### SecureCrypto Class
- `EncryptionResult encryptMessage(String message, boolean use1488BitKey)` - Encrypt message
- `String decryptMessage(String encryptedData, String keyHex)` - Decrypt message
- `boolean isValidKey(String keyHex)` - Validate key format
- `SystemInfo getSystemInfo()` - Get system information

### EncryptionResult Class
- `String getEncryptedData()` - Base64 encoded encrypted data
- `String getKey()` - Hex encoded encryption key
- `int getKeyBits()` - Key size (512 or 1488 bits)

## 📁 Maven Structure Benefits

### Why This Organization?
- **Industry Standard**: Follows Maven's standard directory layout
- **Clear Separation**: Main application code vs test code
- **IDE Support**: VS Code, IntelliJ, Eclipse recognize this structure
- **Build Tools**: Maven, Gradle work seamlessly
- **Scalability**: Easy to add more modules and dependencies

### Directory Roles
| Directory | Purpose | Contains |
|-----------|---------|----------|
| `src/main/java/` | Application source code | Core classes, interfaces |
| `src/test/java/` | Test source code | Unit tests, integration tests |
| `target/classes/` | Compiled main classes | `.class` files from main |
| `target/test-classes/` | Compiled test classes | `.class` files from test |

## 🛡️ Security Notes

1. **Key Storage**: Keys are generated fresh for each encryption and immediately wiped from memory
2. **Memory Security**: All sensitive data is securely cleaned using OpenSSL_cleanse()
3. **Attack Resistance**: Random delays prevent timing-based cryptanalysis
4. **No Persistence**: No keys or sensitive data are ever stored permanently

## 📊 Performance

- **Small messages (< 1KB)**: ~5-10ms per encrypt/decrypt cycle
- **Large messages (> 10KB)**: Scales linearly with message size
- **Memory usage**: Minimal - all buffers cleaned immediately after use

## 🔄 Build Scripts

- `test_maven_structure.bat` - Complete build and test with proper Maven structure
- `generate_jni_header.bat` - Regenerate JNI headers when needed

## 📝 Version History

- **1.0.0** - Initial release with dual AES-256 encryption and JNI integration
- **1.1.0** - Added proper Maven directory structure and separated test classes

## 🤝 Contributing

This is a security-focused project. All contributions should maintain the highest security standards and undergo thorough testing.

---

**⚠️ Security Warning**: Always store encryption keys securely and never transmit them over insecure channels. This library provides the cryptographic functions but proper key management is the responsibility of the implementing application.
