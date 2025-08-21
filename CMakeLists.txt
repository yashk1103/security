cmake_minimum_required(VERSION 3.10)
project(SecureMessaging VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

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

# Main demo executable
add_executable(secure_message 
    src/main.cpp
    src/secure_message.cpp
)

# Test executable
add_executable(test_secure_message
    src/test.cpp
    src/secure_message.cpp
)

# Interactive demo executable (the one you want to run)
add_executable(interactive_secure_message
    src/interactive_main.cpp
    src/interactive_secure_message.cpp
    src/secure_message.cpp
)

# Production executable (clean version without verbose output)
add_executable(production_secure_message
    src/production_main.cpp
    src/interactive_secure_message.cpp
    src/secure_message.cpp
)

# Link libraries
target_link_libraries(secure_message OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(test_secure_message OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(interactive_secure_message OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(production_secure_message OpenSSL::SSL OpenSSL::Crypto)

if(WIN32)
    target_link_libraries(secure_message ws2_32 crypt32)
    target_link_libraries(test_secure_message ws2_32 crypt32)
    target_link_libraries(interactive_secure_message ws2_32 crypt32)
    target_link_libraries(production_secure_message ws2_32 crypt32)
endif()
