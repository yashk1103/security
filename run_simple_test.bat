@echo oecho Compiling Simple Test...
javac -cp . -d target\classes src\main\java\com\securemessaging\*.java
if %ERRORLEVEL% neq 0 (
    echo Failed to compile Java files
    exit /b 1
)

echo Running Simple Test...
java -cp target\classes -Djava.library.path=%JAVA_LIBRARY_PATH% com.securemessaging.SimpleTestRunning Simple SecureCrypto Test...

REM Set library path for Windows DLL
set PATH=%CD%\build\Release;%PATH%
set JAVA_LIBRARY_PATH=%CD%\build\Release

echo Compiling Simple Test...
javac -cp . -d build\java java\SimpleTest.java java\SecureCrypto.java java\EncryptionResult.java java\SystemInfo.java
if %ERRORLEVEL% neq 0 (
    echo Failed to compile Java classes
    exit /b 1
)

echo Running Simple Test...
java -cp build\java -Djava.library.path=%JAVA_LIBRARY_PATH% com.securemessaging.SimpleTest

echo Done!
