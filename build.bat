@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion
pushd "%~dp0"

echo ========================================
echo   MCPE Server Proxy - Cross Compile
echo ========================================
echo.

:: 设置变量
set "PROJECT_NAME=mcpeserverproxy"
set "BUILD_DIR=build"
set "WEB_DIR=web"
set "DIST_DIR=internal\api\dist"
set "MAIN_FILE=cmd\mcpeserverproxy\main.go"

:: 检查 Go 是否安装
where go >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Go is not installed or not in PATH
    exit /b 1
)

:: 检查 Node.js 是否安装
where npm >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Node.js/npm is not installed or not in PATH
    exit /b 1
)

:: 清空 build 目录
echo [1/3] Cleaning build directory...
if exist "%BUILD_DIR%" (
    rmdir /s /q "%BUILD_DIR%" 2>nul
)
mkdir "%BUILD_DIR%"
echo       Done.
echo.

:: 构建 Web 前端 (vite 直接输出到 internal/api/dist)
echo [2/3] Building web frontend...
pushd "%WEB_DIR%"
if not exist "node_modules" (
    echo       Installing dependencies...
    if exist "package-lock.json" (
        call npm ci
    ) else (
        call npm install
    )
    if !errorlevel! neq 0 (
        echo [ERROR] npm install failed
        popd
        popd
        exit /b 1
    )
)
echo       Building production bundle...
call npm run build
if !errorlevel! neq 0 (
    echo [ERROR] Web build failed
    popd
    popd
    exit /b 1
)
popd
if not exist "%DIST_DIR%\\index.html" (
    echo [ERROR] Web dist output not found: %DIST_DIR%\index.html
    popd
    exit /b 1
)
echo       Done.
echo.

:: 交叉编译
echo [3/3] Cross compiling for all platforms...
echo.

set "SUCCESS_COUNT=0"
set "FAIL_COUNT=0"

:: Windows
call :build_target windows amd64 .exe
@REM call :build_target windows 386 .exe
@REM call :build_target windows arm64 .exe

:: Linux
call :build_target linux amd64
@REM call :build_target linux 386
@REM call :build_target linux arm64
@REM call :build_target linux arm

@REM :: macOS
@REM call :build_target darwin amd64
@REM call :build_target darwin arm64

@REM :: FreeBSD
@REM call :build_target freebsd amd64
@REM call :build_target freebsd arm64

@REM echo.
echo ========================================
echo   Build Complete!
echo   Success: %SUCCESS_COUNT%  Failed: %FAIL_COUNT%
echo   Output: %BUILD_DIR%\
echo ========================================
echo.

:: 列出生成的文件
echo Generated files:
echo.
for %%F in ("%BUILD_DIR%\*") do (
    echo   %%~nxF
)

endlocal
pause
popd
exit /b 0

:: 编译函数
:build_target
set "GOOS=%~1"
set "GOARCH=%~2"
set "EXT=%~3"
set "OUTPUT=%BUILD_DIR%\%PROJECT_NAME%_%GOOS%_%GOARCH%%EXT%"

echo       Building %GOOS%/%GOARCH%...

set "CGO_ENABLED=0"
go build -tags=with_utls -ldflags="-s -w" -o "%OUTPUT%" "%MAIN_FILE%"

if %errorlevel% equ 0 (
    echo       [OK] %PROJECT_NAME%_%GOOS%_%GOARCH%%EXT%
    set /a SUCCESS_COUNT+=1
) else (
    echo       [FAIL] %GOOS%/%GOARCH%
    set /a FAIL_COUNT+=1
)
exit /b 0
