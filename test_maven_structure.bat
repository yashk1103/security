@echo off
echo Building and Testing SecureCrypto with Maven Structure...

echo.
echo === STEP 1: Building C++ Components ===
cmake --build build --config Release
if %ERRORLEVEL% neq 0 (
    echo Failed to build C++ components
    exit /b 1
)

echo.
echo === STEP 2: Compiling Java Classes (Maven Structure) ===
if not exist "target\classes" mkdir target\classes
if not exist "target\test-classes" mkdir target\test-classes

REM Compile main classes
javac -cp . -d target\classes src\main\java\com\securemessaging\*.java
if %ERRORLEVEL% neq 0 (
    echo Failed to compile main Java classes
    exit /b 1
)

REM Compile test classes (depends on main classes)
javac -cp target\classes -d target\test-classes src\test\java\com\securemessaging\*.java
if %ERRORLEVEL% neq 0 (
    echo Failed to compile test Java classes
    exit /b 1
)

echo.
echo === STEP 3: Testing Java JNI Integration ===
set PATH=%CD%\build\Release;%PATH%
set JAVA_LIBRARY_PATH=%CD%\build\Release

echo Running Simple Test...
java -cp "target\classes;target\test-classes" "-Djava.library.path=%JAVA_LIBRARY_PATH%" com.securemessaging.SimpleTest

echo.
echo === STEP 4: Running Full Test Suite ===
java -cp "target\classes;target\test-classes" "-Djava.library.path=%JAVA_LIBRARY_PATH%" com.securemessaging.SecureCryptoTest

echo.
echo === ALL TESTS COMPLETED ===
echo.
echo Available components:
echo - C++ Standalone: .\build\Release\secure_crypto.exe
echo - JNI Library: .\build\Release\secure_crypto_jni.dll
echo - Java Main Classes: .\target\classes\com\securemessaging\*.class
echo - Java Test Classes: .\target\test-classes\com\securemessaging\*.class
echo - Simple Test: java -cp "target\classes;target\test-classes" -Djava.library.path=build\Release com.securemessaging.SimpleTest
echo - Full Test: java -cp "target\classes;target\test-classes" -Djava.library.path=build\Release com.securemessaging.SecureCryptoTest
