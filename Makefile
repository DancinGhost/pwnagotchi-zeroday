CXX      ?= g++
CXXFLAGS ?= -std=c++17 -Wall -Wextra -Werror -O2
HARDEN_CXXFLAGS := -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fstack-clash-protection -Wformat -Wformat-security -fPIE
HARDEN_LDFLAGS  := -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack
INCLUDES := -Icore/include -Irender/include
LINUX_INCLUDES := $(INCLUDES) -Iplatforms/linux/backend -Iplatforms/linux/app
BUILD    := build

# Native libpcap capture/injection is optional (mirrors the CMake build): when present we
# compile it in and link it; otherwise zd-linux falls back to the CLI-tool backend
# (airodump-ng/aireplay-ng) at runtime, same as a CMake build without libpcap-dev.
PCAP_CFLAGS := $(shell pkg-config --cflags libpcap 2>/dev/null)
PCAP_LIBS   := $(shell pkg-config --libs libpcap 2>/dev/null)
ifeq ($(PCAP_LIBS),)
    HAVE_PCAP := 0
else
    HAVE_PCAP := 1
endif

.PHONY: all test sim demo linux web-serve clean dist

all: $(BUILD)/test_functional_core $(BUILD)/test_painter $(BUILD)/test_secops \
     $(BUILD)/test_linux_parsers $(BUILD)/test_dot11_frames $(BUILD)/test_linux_shell \
     $(BUILD)/test_esp32_common $(BUILD)/zd_sim

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/test_functional_core: tests/core/test_functional_core.cpp core/include/zd/*.hpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -UNDEBUG -Icore/include tests/core/test_functional_core.cpp -o $@

$(BUILD)/test_painter: tests/render/test_painter.cpp core/include/zd/*.hpp render/include/zd/render/*.hpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -UNDEBUG $(INCLUDES) tests/render/test_painter.cpp -o $@

$(BUILD)/test_secops: tests/core/test_secops.cpp core/include/zd/*.hpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -UNDEBUG -Icore/include tests/core/test_secops.cpp -o $@

$(BUILD)/test_linux_parsers: tests/core/test_linux_parsers.cpp core/include/zd/*.hpp platforms/linux/backend/*.hpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -UNDEBUG -Icore/include -Iplatforms/linux/backend tests/core/test_linux_parsers.cpp -o $@

$(BUILD)/test_dot11_frames: tests/core/test_dot11_frames.cpp core/include/zd/*.hpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -UNDEBUG -Icore/include tests/core/test_dot11_frames.cpp -o $@

$(BUILD)/test_linux_shell: tests/core/test_linux_shell.cpp core/include/zd/*.hpp platforms/linux/backend/*.hpp platforms/linux/app/*.hpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -UNDEBUG $(LINUX_INCLUDES) tests/core/test_linux_shell.cpp -lpthread -o $@

$(BUILD)/test_esp32_common: tests/core/test_esp32_common.cpp core/include/zd/*.hpp platforms/common/*.hpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -fno-exceptions -fno-rtti -UNDEBUG -Icore/include -Iplatforms/common tests/core/test_esp32_common.cpp -o $@

$(BUILD)/zd_sim: platforms/native/main.cpp core/include/zd/*.hpp render/include/zd/render/*.hpp | $(BUILD)
	$(CXX) $(CXXFLAGS) $(HARDEN_CXXFLAGS) $(INCLUDES) platforms/native/main.cpp $(HARDEN_LDFLAGS) -o $@

# Linux desktop CLI/TUI (hybrid backend; native libpcap capture/injection + CLI fallback).
# The Qt6 GUI (zd-gui) is built via CMake: cmake -B build_cmake && cmake --build build_cmake
$(BUILD)/zd-linux: platforms/linux/cli/main.cpp core/include/zd/*.hpp platforms/linux/backend/*.hpp platforms/linux/app/*.hpp | $(BUILD)
	$(CXX) $(CXXFLAGS) $(HARDEN_CXXFLAGS) $(if $(filter 1,$(HAVE_PCAP)),-DZD_WITH_LIBPCAP) $(LINUX_INCLUDES) $(PCAP_CFLAGS) \
		platforms/linux/cli/main.cpp $(HARDEN_LDFLAGS) -lncurses -lpthread $(PCAP_LIBS) -o $@

linux: $(BUILD)/zd-linux

test: $(BUILD)/test_functional_core $(BUILD)/test_painter $(BUILD)/test_secops $(BUILD)/test_linux_parsers $(BUILD)/test_dot11_frames $(BUILD)/test_linux_shell $(BUILD)/test_esp32_common $(BUILD)/zd-linux $(BUILD)/zd_sim
	./$(BUILD)/test_functional_core
	./$(BUILD)/test_painter
	./$(BUILD)/test_secops
	./$(BUILD)/test_linux_parsers
	./$(BUILD)/test_dot11_frames
	./$(BUILD)/test_linux_shell
	./$(BUILD)/test_esp32_common
	python3 tests/scripts/test_flasher.py
	python3 tests/scripts/test_linux_cli.py --zd-linux ./$(BUILD)/zd-linux --zd-sim ./$(BUILD)/zd_sim
	node platforms/web/test_web_core.js

sim: $(BUILD)/zd_sim
	./$(BUILD)/zd_sim

demo: $(BUILD)/zd_sim
	./$(BUILD)/zd_sim --demo

web-serve:
	python3 -m http.server 8080 --bind 127.0.0.1 --directory platforms/web

clean:
	rm -rf $(BUILD) build_cmake dist dist_release

dist:
	./scripts/package_release.sh

