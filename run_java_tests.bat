@echo off
echo Running SecureCrypto Java JNI Tests...

REM Set library path for Windows DLL
set PATH=%CD%\build\Release;%PATH%

REM Set Java library path
set JAVA_LIBRARY_PATH=%CD%\build\Release

echo Compiling Java classes...
javac -cp . -d build\java java\*.java
if %ERRORLEVEL% neq 0 (
    echo Failed to compile Java classes
    exit /b 1
)

echo Running Java tests...
java -cp build\java -Djava.library.path=%JAVA_LIBRARY_PATH% com.securemessaging.SecureCryptoTest

echo Done!
