cmake_minimum_required(VERSION 3.20)
project(GTAVietUpdate LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_definitions(-DUNICODE -D_UNICODE -DNOMINMAX)

# Source and Header files
set(SOURCES
    src/Main.cpp
    src/WebViewManager.cpp
    src/Downloader.cpp
    src/HashVerifier.cpp
    src/IntegrityChecker.cpp
    src/ServerQuery.cpp
    src/GameLauncher.cpp
    src/SelfUpdate.cpp
    resources/Launcher.rc
)

set(HEADERS
    include/Config.h
    include/Types.h
    include/WebViewManager.h
    include/Downloader.h
    include/HashVerifier.h
    include/IntegrityChecker.h
    include/ServerQuery.h
    include/GameLauncher.h
    include/SelfUpdate.h
    resources/resource.h
)

add_executable(GTAVietUpdate WIN32 ${SOURCES} ${HEADERS})

target_include_directories(GTAVietUpdate PRIVATE include resources)

# System and Windows Runtime Libraries
target_link_libraries(GTAVietUpdate PRIVATE
    winhttp
    ws2_32
    advapi32
    crypt32
    dwmapi
    shlwapi
    shell32
    user32
    gdi32
    ole32
)
