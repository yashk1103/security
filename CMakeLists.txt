cmake_minimum_required(VERSION 3.10)
project(SecureMessaging VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Java and JNI
find_package(JNI REQUIRED)

# Set OpenSSL paths manually for Windows
if(WIN32)
    set(OPENSSL_ROOT_DIR "C:/Program Files/OpenSSL-Win64")
    set(OPENSSL_INCLUDE_DIR "C:/Program Files/OpenSSL-Win64/include")
    set(OPENSSL_CRYPTO_LIBRARY "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MD/libcrypto.lib")
    set(OPENSSL_SSL_LIBRARY "C:/Program Files/OpenSSL-Win64/lib/VC/x64/MD/libssl.lib")
    set(OPENSSL_LIBRARIES ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})
    
    # Create imported targets manually
    add_library(OpenSSL::SSL UNKNOWN IMPORTED)
    set_target_properties(OpenSSL::SSL PROPERTIES IMPORTED_LOCATION "${OPENSSL_SSL_LIBRARY}")
    set_target_properties(OpenSSL::SSL PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE_DIR}")
    
    add_library(OpenSSL::Crypto UNKNOWN IMPORTED)
    set_target_properties(OpenSSL::Crypto PROPERTIES IMPORTED_LOCATION "${OPENSSL_CRYPTO_LIBRARY}")
    set_target_properties(OpenSSL::Crypto PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE_DIR}")
else()
    find_package(OpenSSL REQUIRED)
endif()

include_directories(include)
include_directories(${JNI_INCLUDE_DIRS})

# Core crypto library
add_library(secure_crypto_core STATIC
    src/secure_crypto_core.cpp
)

# Standalone executable using core
add_executable(secure_crypto
    src/secure_crypto.cpp
)

# JNI shared library using core
add_library(secure_crypto_jni SHARED
    src/secure_crypto_jni.cpp
)

# Set export definitions for JNI library
if(WIN32)
    set_target_properties(secure_crypto_jni PROPERTIES 
        WINDOWS_EXPORT_ALL_SYMBOLS TRUE
    )
endif()

# Link libraries for core
target_link_libraries(secure_crypto_core OpenSSL::SSL OpenSSL::Crypto)

# Link libraries for executable
target_link_libraries(secure_crypto secure_crypto_core OpenSSL::SSL OpenSSL::Crypto)

# Link libraries for JNI library
target_link_libraries(secure_crypto_jni secure_crypto_core OpenSSL::SSL OpenSSL::Crypto)

if(WIN32)
    target_link_libraries(secure_crypto ws2_32 crypt32)
    target_link_libraries(secure_crypto_jni ws2_32 crypt32)
endif()
