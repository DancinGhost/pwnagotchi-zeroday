cmake_minimum_required(VERSION 3.16)
project(pwnagotchi-zeroday LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Portable zero-dependency functional core (header-only)
add_library(zd_core INTERFACE)
target_include_directories(zd_core INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/core/include")

# Portable immediate-mode painter & RGB565 software surface (header-only)
add_library(zd_render INTERFACE)
target_include_directories(zd_render INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/render/include")
target_link_libraries(zd_render INTERFACE zd_core)

if(MSVC)
    set(ZD_WARN_FLAGS /W4 /WX)
    set(ZD_HARDEN_COMPILE_FLAGS)
    set(ZD_HARDEN_LINK_FLAGS)
else()
    set(ZD_WARN_FLAGS -Wall -Wextra -Werror)
    set(ZD_HARDEN_COMPILE_FLAGS
        -fstack-protector-strong
        -fstack-clash-protection
        -Wformat
        -Wformat-security
        -fPIE
        $<$<CONFIG:Release,RelWithDebInfo,MinSizeRel>:-D_FORTIFY_SOURCE=2>)
    set(ZD_HARDEN_LINK_FLAGS -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack)
endif()

# Native desktop / Linux SBC terminal simulator
add_executable(zd_sim platforms/native/main.cpp)
target_link_libraries(zd_sim PRIVATE zd_render)
target_compile_options(zd_sim PRIVATE ${ZD_WARN_FLAGS} ${ZD_HARDEN_COMPILE_FLAGS})
target_link_options(zd_sim PRIVATE ${ZD_HARDEN_LINK_FLAGS})

# ----------------------------------------------------------------------------------------
# Linux desktop targets (CLI/TUI + Qt6 GUI) with hybrid WiFi backend.
# Native libpcap frame capture/injection is used when available; otherwise the CLI-tool
# backend (iw / nmcli / airodump-ng / aireplay-ng) is the fallback at runtime.
# ----------------------------------------------------------------------------------------
if(UNIX AND NOT APPLE)
    find_package(PkgConfig QUIET)
    if(PkgConfig_FOUND)
        pkg_check_modules(LIBPCAP IMPORTED_TARGET libpcap)
    endif()
    if(NOT LIBPCAP_FOUND)
        find_library(PCAP_LIB pcap)
        find_path(PCAP_INC pcap/pcap.h)
    endif()

    set(ZD_LINUX_INCLUDES
        "${CMAKE_CURRENT_SOURCE_DIR}/core/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/render/include"
        "${CMAKE_CURRENT_SOURCE_DIR}/platforms/linux/backend"
        "${CMAKE_CURRENT_SOURCE_DIR}/platforms/linux/app")

    # --- CLI / ncurses TUI ---
    set(CURSES_NEED_NCURSES TRUE)
    find_package(Curses)
    if(Curses_FOUND)
        add_executable(zd-linux platforms/linux/cli/main.cpp)
        target_include_directories(zd-linux PRIVATE ${ZD_LINUX_INCLUDES} ${CURSES_INCLUDE_DIRS})
        target_link_libraries(zd-linux PRIVATE ${CURSES_LIBRARIES} pthread)
        target_compile_options(zd-linux PRIVATE ${ZD_WARN_FLAGS} ${ZD_HARDEN_COMPILE_FLAGS})
        target_link_options(zd-linux PRIVATE ${ZD_HARDEN_LINK_FLAGS})
        if(LIBPCAP_FOUND)
            target_compile_definitions(zd-linux PRIVATE ZD_WITH_LIBPCAP)
            target_link_libraries(zd-linux PRIVATE PkgConfig::LIBPCAP)
        elseif(PCAP_LIB)
            target_compile_definitions(zd-linux PRIVATE ZD_WITH_LIBPCAP)
            target_include_directories(zd-linux PRIVATE ${PCAP_INC})
            target_link_libraries(zd-linux PRIVATE ${PCAP_LIB})
        endif()
    else()
        message(STATUS "ncurses not found: skipping zd-linux CLI target")
    endif()

    # --- Qt6 GUI ---
    find_package(Qt6 QUIET COMPONENTS Widgets)
    if(Qt6_FOUND)
        add_executable(zd-gui
            platforms/linux/gui/main.cpp
            platforms/linux/gui/main_window.cpp
            platforms/linux/gui/main_window.hpp
            platforms/linux/gui/pet_widget.hpp)
        # Scoped to this target only: CMAKE_AUTOMOC is a global switch and would
        # otherwise make every later target in this file (including the non-Qt
        # test executables) pay for moc/autogen machinery they never use.
        set_target_properties(zd-gui PROPERTIES AUTOMOC ON)
        target_include_directories(zd-gui PRIVATE ${ZD_LINUX_INCLUDES})
        target_link_libraries(zd-gui PRIVATE Qt6::Widgets pthread)
        target_compile_options(zd-gui PRIVATE ${ZD_WARN_FLAGS} ${ZD_HARDEN_COMPILE_FLAGS})
        target_link_options(zd-gui PRIVATE ${ZD_HARDEN_LINK_FLAGS})
        if(LIBPCAP_FOUND)
            target_compile_definitions(zd-gui PRIVATE ZD_WITH_LIBPCAP)
            target_link_libraries(zd-gui PRIVATE PkgConfig::LIBPCAP)
        elseif(PCAP_LIB)
            target_compile_definitions(zd-gui PRIVATE ZD_WITH_LIBPCAP)
            target_include_directories(zd-gui PRIVATE ${PCAP_INC})
            target_link_libraries(zd-gui PRIVATE ${PCAP_LIB})
        endif()
    else()
        message(STATUS "Qt6 Widgets not found: skipping zd-gui target")
    endif()
endif()

# Automated unit tests
enable_testing()

add_executable(test_functional_core tests/core/test_functional_core.cpp)
target_link_libraries(test_functional_core PRIVATE zd_core)
target_compile_options(test_functional_core PRIVATE ${ZD_WARN_FLAGS})
add_test(NAME core_functional_tests COMMAND test_functional_core)

add_executable(test_painter tests/render/test_painter.cpp)
target_link_libraries(test_painter PRIVATE zd_render)
target_compile_options(test_painter PRIVATE ${ZD_WARN_FLAGS})
add_test(NAME render_and_hal_tests COMMAND test_painter)

add_executable(test_secops tests/core/test_secops.cpp)
target_link_libraries(test_secops PRIVATE zd_core)
target_compile_options(test_secops PRIVATE ${ZD_WARN_FLAGS})
add_test(NAME security_engine_tests COMMAND test_secops)

add_executable(test_linux_parsers tests/core/test_linux_parsers.cpp)
target_include_directories(test_linux_parsers PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/core/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/platforms/linux/backend")
target_compile_options(test_linux_parsers PRIVATE ${ZD_WARN_FLAGS})
add_test(NAME linux_backend_parser_tests COMMAND test_linux_parsers)

add_executable(test_dot11_frames tests/core/test_dot11_frames.cpp)
target_link_libraries(test_dot11_frames PRIVATE zd_core)
target_compile_options(test_dot11_frames PRIVATE ${ZD_WARN_FLAGS})
add_test(NAME dot11_frame_builder_tests COMMAND test_dot11_frames)

add_executable(test_esp32_common tests/core/test_esp32_common.cpp)
target_link_libraries(test_esp32_common PRIVATE zd_core)
target_include_directories(test_esp32_common PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/platforms/common")
target_compile_options(test_esp32_common PRIVATE ${ZD_WARN_FLAGS})
if(NOT MSVC AND NOT CMAKE_CXX_FLAGS MATCHES "fsanitize")
    target_compile_options(test_esp32_common PRIVATE -fno-exceptions -fno-rtti)
endif()
add_test(NAME esp32_common_tests COMMAND test_esp32_common)

set(ZD_TEST_TARGETS
    test_functional_core
    test_painter
    test_secops
    test_linux_parsers
    test_dot11_frames
    test_esp32_common)

if(UNIX AND NOT APPLE)
    add_executable(test_linux_shell tests/core/test_linux_shell.cpp)
    target_include_directories(test_linux_shell PRIVATE ${ZD_LINUX_INCLUDES})
    target_link_libraries(test_linux_shell PRIVATE pthread)
    target_compile_options(test_linux_shell PRIVATE ${ZD_WARN_FLAGS})
    add_test(NAME linux_shell_tests COMMAND test_linux_shell)
    list(APPEND ZD_TEST_TARGETS test_linux_shell)

    if(Qt6_FOUND)
        find_package(Qt6 QUIET COMPONENTS Test)
        if(Qt6Test_FOUND)
            add_executable(test_gui
                tests/gui/test_gui.cpp
                platforms/linux/gui/main_window.cpp
                platforms/linux/gui/main_window.hpp
                platforms/linux/gui/pet_widget.hpp)
            set_target_properties(test_gui PROPERTIES AUTOMOC ON)
            target_include_directories(test_gui PRIVATE ${ZD_LINUX_INCLUDES} "${CMAKE_CURRENT_SOURCE_DIR}/platforms/linux/gui")
            target_link_libraries(test_gui PRIVATE Qt6::Widgets Qt6::Test pthread)
            target_compile_options(test_gui PRIVATE ${ZD_WARN_FLAGS})
            if(LIBPCAP_FOUND)
                target_compile_definitions(test_gui PRIVATE ZD_WITH_LIBPCAP)
                target_link_libraries(test_gui PRIVATE PkgConfig::LIBPCAP)
            elseif(PCAP_LIB)
                target_compile_definitions(test_gui PRIVATE ZD_WITH_LIBPCAP)
                target_include_directories(test_gui PRIVATE ${PCAP_INC})
                target_link_libraries(test_gui PRIVATE ${PCAP_LIB})
            endif()
            add_test(NAME linux_gui_tests COMMAND test_gui)
            set_tests_properties(linux_gui_tests PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
            list(APPEND ZD_TEST_TARGETS test_gui)
        endif()
    endif()
endif()

# The tests rely on assert(). Release builds define NDEBUG, which would compile every
# assertion away (making the tests no-ops and tripping -Werror on assert-only variables),
# so force assertions back on for the test executables regardless of build type.
foreach(zd_test ${ZD_TEST_TARGETS})
    if(MSVC)
        target_compile_options(${zd_test} PRIVATE /UNDEBUG)
    else()
        target_compile_options(${zd_test} PRIVATE -UNDEBUG)
    endif()
endforeach()

find_program(PYTHON3_EXECUTABLE python3)
if(PYTHON3_EXECUTABLE)
    add_test(
        NAME flasher_script_tests
        COMMAND "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/scripts/test_flasher.py"
    )
    if(TARGET zd-linux AND TARGET zd_sim)
        add_test(
            NAME linux_cli_tests
            COMMAND "${PYTHON3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/scripts/test_linux_cli.py"
                    --zd-linux "$<TARGET_FILE:zd-linux>"
                    --zd-sim "$<TARGET_FILE:zd_sim>"
        )
    endif()
endif()

find_program(NODE_EXECUTABLE node)
if(NODE_EXECUTABLE)
    add_test(
        NAME web_and_parity_tests
        COMMAND "${NODE_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/platforms/web/test_web_core.js"
    )
endif()
