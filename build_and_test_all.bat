@echo off
echo Building and Testing Complete SecureCrypto System...

echo.
echo === STEP 1: Building C++ Components ===
cmake --build build --config Release
if %ERRORLEVEL% neq 0 (
    echo Failed to build C++ components
    exit /b 1
)

echo.
echo === STEP 2: Compiling Java Classes ===
javac -cp . -d build\java java\*.java
if %ERRORLEVEL% neq 0 (
    echo Failed to compile Java classes
    exit /b 1
)

echo.
echo === STEP 3: Testing C++ Standalone ===
echo Testing C++ executable functionality...
echo 3 | .\build\Release\secure_crypto.exe

echo.
echo === STEP 4: Testing Java JNI Integration ===
set PATH=%CD%\build\Release;%PATH%
set JAVA_LIBRARY_PATH=%CD%\build\Release
java -cp build\java -Djava.library.path=%JAVA_LIBRARY_PATH% com.securemessaging.SecureCryptoTest

echo.
echo === BUILD AND TEST COMPLETE ===
echo.
echo Available components:
echo - C++ Standalone: .\build\Release\secure_crypto.exe
echo - JNI Library: .\build\Release\secure_crypto_jni.dll
echo - Java Classes: .\build\java\com\securemessaging\*.class
echo - Java Test: java -cp build\java -Djava.library.path=build\Release com.securemessaging.SecureCryptoTest
