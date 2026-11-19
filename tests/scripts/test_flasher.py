import importlib.util
import os
import sys
import tempfile
import unittest
from unittest import mock

FLASHER_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "scripts", "flasher", "flash.py")
)
SPEC = importlib.util.spec_from_file_location("zd_flasher", FLASHER_PATH)
flasher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(flasher)


class TestFlasherScript(unittest.TestCase):
    def test_is_safe_port_name(self):
        self.assertTrue(flasher.is_safe_port_name("/dev/ttyUSB0"))
        self.assertTrue(flasher.is_safe_port_name("COM3"))
        self.assertFalse(flasher.is_safe_port_name(""))
        self.assertFalse(flasher.is_safe_port_name("--chip"))
        self.assertFalse(flasher.is_safe_port_name("-p"))
        self.assertFalse(flasher.is_safe_port_name("/dev/ttyUSB0\n"))

    def test_locate_factory_binary_refuses_unmerged_bins(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Unmerged images must NOT be returned for 0x0 flashing.
            for name in ("firmware.bin", "bootloader.bin", "partitions.bin"):
                open(os.path.join(tmp, name), "wb").close()
            self.assertIsNone(flasher.locate_factory_binary(tmp))

            # Flag-like factory filename is ignored.
            open(os.path.join(tmp, "-evil-factory.bin"), "wb").close()
            self.assertIsNone(flasher.locate_factory_binary(tmp))

            # Valid merged factory binary is found.
            expected = os.path.join(tmp, "pwnagotchi-zd-t-deck-plus-factory.bin")
            open(expected, "wb").close()
            self.assertEqual(flasher.locate_factory_binary(tmp), expected)

    def test_windows_missing_pyserial_does_not_crash(self):
        with mock.patch.object(sys, "platform", "win32"):
            with mock.patch.dict(sys.modules, {"serial": None, "serial.tools": None, "serial.tools.list_ports": None}):
                ports = flasher.get_serial_ports()
                self.assertEqual(ports, [])


if __name__ == "__main__":
    unittest.main()
