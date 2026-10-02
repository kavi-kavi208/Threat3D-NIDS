@echo off
@REM ----------------------------------------------------------------------------
@REM Maven Wrapper Script for Windows
@REM ----------------------------------------------------------------------------

setlocal

set "DIR=%~dp0"

if exist "%DIR%.mvn\apache-maven-3.9.8\bin\mvn.cmd" (
    "%DIR%.mvn\apache-maven-3.9.8\bin\mvn.cmd" %*
    exit /b %ERRORLEVEL%
)

echo [INFO] Apache Maven not found locally. Downloading Apache Maven 3.9.8...
if not exist "%DIR%.mvn" mkdir "%DIR%.mvn"

curl.exe -L -s -o "%DIR%.mvn\maven.zip" https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.8/apache-maven-3.9.8-bin.zip
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to download Maven. Please check your internet connection.
    exit /b 1
)

powershell -Command "Expand-Archive -Path '%DIR%.mvn\maven.zip' -DestinationPath '%DIR%.mvn' -Force"
del /f /q "%DIR%.mvn\maven.zip"

"%DIR%.mvn\apache-maven-3.9.8\bin\mvn.cmd" %*
exit /b %ERRORLEVEL%
