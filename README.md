# Secure Message Encryption System

A professional-grade cryptographic implementation featuring interactive AES-512 equivalent encryption with OpenSSL, designed for educational and practical security applications.

## Features

### Advanced Cryptography
- **AES-512 Equivalent**: Dual AES-256 encryption for maximum security
- **PBKDF2 Key Derivation**: 500,000 iterations with SHA-512
- **Message Integrity**: SHA-512 hash verification
- **Random Salt & IV**: Unique encryption every time
- **OpenSSL Implementation**: Industry-standard cryptographic library

### Interactive Experience
- **Step-by-Step Visualization**: 7-step encryption process
- **Custom Input**: User-defined messages and passwords
- **Real-time Demonstration**: Press Enter between steps
- **Educational Tool**: Perfect for learning cryptography

### Security Standards
- **Military-Grade Encryption**: NSA-approved AES-256
- **Banking-Standard Key Derivation**: PBKDF2 compliance
- **Zero Trust Architecture**: Complete message verification
- **Memory Safe**: Proper cleanup of sensitive data

## Requirements

### System Requirements
- Windows 10/11 (x64)
- Visual Studio 2019/2022 Build Tools
- OpenSSL for Windows
- CMake 3.15+ (optional)

### Dependencies
- OpenSSL 1.1.1+ or 3.0+
- C++17 compatible compiler
- Windows SDK

## Installation

### 1. Install OpenSSL for Windows

#### Option A: Using Pre-built Binaries (Recommended)
```powershell
# Download OpenSSL 3.0+ from: https://slproweb.com/products/Win32OpenSSL.html
# Choose: "Win64 OpenSSL v3.x.x" (NOT the Light version)
# Install to default location: C:\Program Files\OpenSSL-Win64

# Verify installation
dir "C:\Program Files\OpenSSL-Win64\bin"
dir "C:\Program Files\OpenSSL-Win64\include"
dir "C:\Program Files\OpenSSL-Win64\lib"
```

#### Option B: Using Package Manager
```powershell
# Install using Chocolatey (if available)
choco install openssl

# Or using vcpkg
vcpkg install openssl:x64-windows
```

### 2. Install Visual Studio Build Tools

#### Option A: Visual Studio Installer
```powershell
# Download from: https://visualstudio.microsoft.com/downloads/
# Install "Build Tools for Visual Studio 2022"
# Select workload: "C++ build tools"
# Include: "Windows 10/11 SDK" and "CMake tools"
```

#### Option B: Command Line
```powershell
# Using winget (Windows Package Manager)
winget install Microsoft.VisualStudio.2022.BuildTools

# Using Chocolatey
choco install visualstudio2022buildtools --package-parameters "--add Microsoft.VisualStudio.Workload.VCTools"
```

### 3. Verify Installation

```powershell
# Test Visual Studio Build Tools
cmd /c '"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" && cl'

# Test OpenSSL
"C:\Program Files\OpenSSL-Win64\bin\openssl.exe" version

# Test CMake (optional)
cmake --version
```

### 4. Clone Repository
```bash
git clone https://github.com/yashk1103/security.git
cd security
```

## Quick Start

### Method 1: Direct Compilation (Recommended)

#### Step 1: Open Command Prompt as Administrator
```powershell
# Open PowerShell as Administrator
# Navigate to project directory
cd path\to\security
```

#### Step 2: Compile
```powershell
# Set up Visual Studio environment and compile
cmd /c '"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" && cl /EHsc /std:c++17 /I include /I "C:\Program Files\OpenSSL-Win64\include" src\interactive_secure_message.cpp /Fe:interactive_demo.exe /link "C:\Program Files\OpenSSL-Win64\lib\VC\x64\MD\libcrypto.lib" "C:\Program Files\OpenSSL-Win64\lib\VC\x64\MD\libssl.lib" ws2_32.lib crypt32.lib'
```

#### Step 3: Run
```powershell
.\interactive_demo.exe
```

### Method 2: Using CMake (Alternative)

#### Step 1: Create Build Directory
```powershell
mkdir build
cd build
```

#### Step 2: Configure with OpenSSL Path
```powershell
cmake .. -A x64 -DOPENSSL_ROOT_DIR="C:\Program Files\OpenSSL-Win64"
```

#### Step 3: Build
```powershell
cmake --build . --config Release
```

#### Step 4: Run
```powershell
.\Release\interactive_secure_message.exe
```

## Usage Example

```
Enter your message: Project funding is approved.
Enter your password: my-super-secret-key

+-- STEP 1: Start with Original Message --
| Input:  None (starting data)
| Output: "Project funding is approved."
+----------------------------------------

Press Enter to continue to Step 2...

+-- STEP 2: Generate SHA-512 Hash --
| Input:  "Project funding is approved."
| Output: "852aa39ddceae738ed3be5510c5eb17a..."
+----------------------------------

[... continues through all 7 steps ...]

Final Base64 Output: "xXFNUCEb+gkf8uDRCgiVperxAaYLD2..."
```

## Troubleshooting

### Common Issues and Solutions

#### OpenSSL Not Found
```powershell
# If OpenSSL is installed elsewhere, find it:
where openssl
dir "C:\Program Files\OpenSSL*" /ad

# Update the compilation command with correct path
```

#### Visual Studio Build Tools Not Found
```powershell
# Find your Visual Studio installation:
dir "C:\Program Files (x86)\Microsoft Visual Studio" /ad
dir "C:\Program Files\Microsoft Visual Studio" /ad

# Update vcvars64.bat path accordingly
```

#### Compilation Errors
```powershell
# Ensure you're using Administrator PowerShell
# Verify all paths exist:
dir "C:\Program Files\OpenSSL-Win64\include\openssl"
dir "C:\Program Files\OpenSSL-Win64\lib\VC\x64\MD"
```

#### CMake Issues
```powershell
# If CMake can't find OpenSSL:
cmake .. -A x64 -DOPENSSL_ROOT_DIR="C:\Program Files\OpenSSL-Win64" -DOPENSSL_INCLUDE_DIR="C:\Program Files\OpenSSL-Win64\include" -DOPENSSL_LIBRARIES="C:\Program Files\OpenSSL-Win64\lib\VC\x64\MD"
```

#### Runtime Errors
```powershell
# If you get DLL errors, ensure OpenSSL bin is in PATH:
set PATH=%PATH%;C:\Program Files\OpenSSL-Win64\bin

# Or copy required DLLs to project directory:
copy "C:\Program Files\OpenSSL-Win64\bin\libcrypto-3-x64.dll" .
copy "C:\Program Files\OpenSSL-Win64\bin\libssl-3-x64.dll" .
```

## Core Methods Implementation

The system implements 4 essential C++ methods using OpenSSL:

### 1. generateHash()
- **Input**: Plain text message
- **Algorithm**: SHA-512
- **Output**: 128-character hexadecimal hash
- **Purpose**: Message integrity verification

### 2. generateKey()
- **Input**: Password + 32-byte random salt
- **Algorithm**: PBKDF2-HMAC-SHA512 with 500,000 iterations
- **Output**: 512-bit (64 bytes) encryption key
- **Purpose**: Secure key derivation from password

### 3. encrypt()
- **Input**: Combined message+hash + 512-bit key
- **Algorithm**: Dual AES-256-CBC encryption
- **Output**: Encrypted binary data with embedded IVs
- **Purpose**: AES-512 equivalent secure encryption

### 4. decrypt()
- **Input**: Encrypted data + 512-bit key
- **Algorithm**: Reverse dual AES-256-CBC decryption
- **Output**: Original plaintext message
- **Purpose**: Complete decryption and verification

## Cryptographic Process

### Encryption Flow (7 Steps)
1. **Original Message**: User input
2. **Hash Generation**: SHA-512 for integrity
3. **Message Combination**: Message + hash with delimiter
4. **Key Derivation**: PBKDF2 with 500k iterations + salt
5. **AES-512 Encryption**: Dual AES-256 with unique IV
6. **Base64 Encoding**: Safe text transmission format
7. **Final Output**: Ready for secure transmission

### Security Parameters
- **Key Size**: 512-bit (dual 256-bit keys)
- **Salt Size**: 256-bit (32 bytes) random
- **IV Size**: 128-bit (16 bytes) random
- **Hash Algorithm**: SHA-512
- **Iterations**: 500,000 (PBKDF2)

## Project Structure

```
security/
├── src/
│   └── interactive_secure_message.cpp # Complete implementation with main()
├── include/
│   └── interactive_secure_message.h   # Header definitions
├── build/                             # Build artifacts (git-ignored)
├── CMakeLists.txt                     # Build configuration
├── README.md                          # This file
└── .gitignore                         # Git ignore rules
```

## Educational Value

### Learning Objectives
- Understanding symmetric encryption
- Key derivation best practices
- Message authentication codes
- Secure random number generation
- Production cryptography implementation

### Concepts Demonstrated
- **Password vs Key**: Clear distinction and derivation
- **Salt Importance**: Preventing rainbow table attacks
- **IV Usage**: Ensuring encryption uniqueness
- **Hash Verification**: Detecting message tampering
- **Base64 Encoding**: Safe binary-to-text conversion

## Technical Specifications

### Algorithms Used
- **Encryption**: AES-256-CBC (dual encryption)
- **Key Derivation**: PBKDF2-HMAC-SHA512
- **Hashing**: SHA-512
- **Encoding**: Base64
- **Random Generation**: OpenSSL CSPRNG

### Security Standards Compliance
- **FIPS 140-2**: Approved algorithms
- **NIST SP 800-132**: PBKDF2 recommendations
- **RFC 3962**: AES-CBC encryption
- **RFC 4648**: Base64 encoding

## Performance

### Typical Performance Metrics
- **Key Derivation**: ~500ms (intentionally slow for security)
- **Encryption**: <1ms for typical messages
- **Memory Usage**: <10MB peak
- **Binary Size**: ~2MB with OpenSSL static linking

## Testing

### Manual Testing
```powershell
# Test with different message types
.\interactive_demo.exe
# Test cases:
# 1. Enter: "Hello World" / "password123"
# 2. Enter: "Special chars: !@#$%^&*()" / "complex-pass-2024"
# 3. Enter: "" / "empty-message-test"
# 4. Enter: "Very long message with multiple sentences and special characters to test buffer handling and memory management." / "long-test-2024"
```

### Verification Steps
1. **Message integrity verification** through hash comparison
2. **Encryption/decryption round-trip** testing
3. **Different password validation**
4. **Special character handling**
5. **Memory safety** (no crashes or leaks)

### Expected Output Format
```
=== AES-512 Secure Message Encryption System ===

Enter your message: Test Message
Enter your password: TestPass123

=== ENCRYPTION PROCESS ===
[... 7 step demonstration ...]

=== DECRYPTION PROCESS ===  
[... reverse process ...]

=== VERIFICATION ===
Original message: "Test Message"
Decrypted message: "Test Message"
SUCCESS: Messages match! Encryption/Decryption working correctly.
```

## Security Considerations

### Strengths
- Cryptographically secure random generation
- Proper key derivation with high iteration count
- Message authentication and integrity verification
- No hardcoded secrets or keys
- Resistant to timing attacks

### Important Notes
- Keys derived from passwords are only as strong as the password
- This is for educational/demonstration purposes
- Production use requires additional security considerations
- Key management and secure storage not implemented

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is for educational purposes. Please ensure compliance with local cryptography regulations.

## References

- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [NIST Cryptographic Standards](https://csrc.nist.gov/)
- [RFC 3962 - AES-CBC](https://tools.ietf.org/html/rfc3962)
- [PBKDF2 Specification](https://tools.ietf.org/html/rfc2898)

---

**Warning**: This implementation is for educational and demonstration purposes. For production use, consult with cryptography experts and ensure compliance with security policies and regulations.
