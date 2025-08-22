@echo off
echo Generating JNI headers for SecureCrypto...

REM Create output directories
if not exist "build\java" mkdir build\java
if not exist "include" mkdir include

REM Compile Java classes and generate JNI header in one step
echo Compiling Java classes and generating JNI header...
javac -h include -d target\classes src\main\java\com\securemessaging\*.java
if %ERRORLEVEL% neq 0 (
    echo Failed to compile Java classes or generate JNI header
    exit /b 1
)

echo JNI header generated successfully: include\com_securemessaging_SecureCrypto.h
echo Done!
