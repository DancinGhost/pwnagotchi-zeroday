import hashlib
import importlib.util
import io
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

    def test_verify_sha256_manifest_cases(self):
        with tempfile.TemporaryDirectory() as tmp:
            fw = os.path.join(tmp, "pwnagotchi-zd-m5stick-c-factory.bin")
            payload = b"factory-image-test-bytes"
            with open(fw, "wb") as fh:
                fh.write(payload)
            digest = hashlib.sha256(payload).hexdigest()

            # Without a manifest present locally, fail closed unless require_manifest=False (--skip-verify).
            ok_none, msg_none = flasher.verify_sha256(fw)
            self.assertFalse(ok_none, msg_none)
            ok_skip, _ = flasher.verify_sha256(fw, require_manifest=False)
            self.assertTrue(ok_skip)

            # Matching .sha256 passes.
            sha_file = fw + ".sha256"
            with open(sha_file, "w", encoding="utf-8") as fh:
                fh.write(f"{digest}  pwnagotchi-zd-m5stick-c-factory.bin\n")
            ok_match, msg_match = flasher.verify_sha256(fw)
            self.assertTrue(ok_match, msg_match)

            # Mismatched .sha256 fails closed.
            with open(sha_file, "w", encoding="utf-8") as fh:
                fh.write(("0" * 64) + "  pwnagotchi-zd-m5stick-c-factory.bin\n")
            ok_bad, _ = flasher.verify_sha256(fw)
            self.assertFalse(ok_bad)

            # SHA256SUMS.txt missing the target filename fails closed.
            os.remove(sha_file)
            with open(os.path.join(tmp, "SHA256SUMS.txt"), "w", encoding="utf-8") as fh:
                fh.write(f"{digest}  other-board-factory.bin\n")
            ok_missing, _ = flasher.verify_sha256(fw)
            self.assertFalse(ok_missing)

    def test_ensure_esptool_refuses_unhashed_pip_by_default(self):
        with mock.patch("subprocess.run", side_effect=FileNotFoundError("no esptool")):
            with mock.patch("sys.stdout", new_callable=io.StringIO):
                with self.assertRaises(SystemExit) as cm:
                    flasher.ensure_esptool(allow_unhashed_pip=False)
                self.assertEqual(cm.exception.code, 1)

    def test_main_multiport_abort_does_not_default_silently(self):
        with tempfile.TemporaryDirectory() as tmp:
            fw = os.path.join(tmp, "pwnagotchi-zd-m5stick-c-factory.bin")
            payload = b"test-fw"
            with open(fw, "wb") as fh:
                fh.write(payload)
            digest = hashlib.sha256(payload).hexdigest()
            with open(fw + ".sha256", "w", encoding="utf-8") as fh:
                fh.write(f"{digest}  pwnagotchi-zd-m5stick-c-factory.bin\n")
            cwd = os.getcwd()
            try:
                os.chdir(tmp)
                with mock.patch.object(flasher, "get_serial_ports", return_value=["/dev/ttyUSB0", "/dev/ttyUSB1"]):
                    with mock.patch("builtins.input", side_effect=["invalid", "q"]):
                        with mock.patch("sys.stdout", new_callable=io.StringIO):
                            with self.assertRaises(SystemExit) as cm:
                                flasher.main([])
                            self.assertEqual(cm.exception.code, 0)
            finally:
                os.chdir(cwd)


if __name__ == "__main__":
    unittest.main()
