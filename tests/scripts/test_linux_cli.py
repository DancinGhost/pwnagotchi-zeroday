#!/usr/bin/env python3
"""Integration tests for Linux CLI binaries (`zd-linux` and `zd_sim`)."""

import argparse
import os
import subprocess
import sys
import tempfile
import unittest


ZDSIM_BIN = ""
ZDLINUX_BIN = ""


def resolve_default_bin(name):
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    for folder in ("build_cmake", "build"):
        candidate = os.path.join(root, folder, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return ""


class TestLinuxCliBinaries(unittest.TestCase):
    def test_zd_sim_cli_flags_and_ppm(self):
        if not ZDSIM_BIN:
            self.skipTest("zd_sim binary not found")

        help_res = subprocess.run([ZDSIM_BIN, "--help"], capture_output=True, text=True, check=False)
        self.assertEqual(help_res.returncode, 0)
        self.assertIn("Usage: zd_sim", help_res.stdout)

        bad_flag = subprocess.run(
            [ZDSIM_BIN, "--unknown-flag"], capture_output=True, text=True, check=False
        )
        self.assertNotEqual(bad_flag.returncode, 0)

        missing_arg = subprocess.run([ZDSIM_BIN, "--theme"], capture_output=True, text=True, check=False)
        self.assertNotEqual(missing_arg.returncode, 0)

        with tempfile.TemporaryDirectory() as tmp:
            ppm = os.path.join(tmp, "out.ppm")
            ok = subprocess.run(
                [ZDSIM_BIN, "--demo", "--no-color", "--size", "plus", "--ppm", ppm],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(ok.returncode, 0, msg=ok.stderr)
            with open(ppm, "rb") as fh:
                header = fh.read(16)
            self.assertTrue(header.startswith(b"P6\n240 135\n255\n"))

    def test_zd_linux_cli_validation_and_replay(self):
        if not ZDLINUX_BIN:
            self.skipTest("zd-linux binary not found")

        help_res = subprocess.run([ZDLINUX_BIN, "--help"], capture_output=True, text=True, check=False)
        self.assertEqual(help_res.returncode, 0)
        self.assertIn("zd-linux", help_res.stdout)

        for bad_args in (
            ["--not-a-flag"],
            ["--count", "abc"],
            ["--channel", "999"],
            ["--iface"],
        ):
            res = subprocess.run([ZDLINUX_BIN] + bad_args, capture_output=True, text=True, check=False)
            self.assertNotEqual(res.returncode, 0, msg=f"expected failure for {bad_args}")

        # Verify session replay mode works cleanly end-to-end without hardware privileges.
        with tempfile.TemporaryDirectory() as tmp:
            zds_path = os.path.join(tmp, "sample.zds")
            with open(zds_path, "w", encoding="utf-8") as fh:
                fh.write("AP|1000|02:aa:bb:cc:dd:01|LabNet|6|-40|4|0\n")
                fh.write("AP|1100|02:aa:bb:cc:dd:02|LabNet|6|-45|1|0\n")
                fh.write("PROBE|1200|02:11:22:33:44:55|linksys\n")
            env = {**os.environ, "HOME": tmp}
            res = subprocess.run(
                [ZDLINUX_BIN, "replay", zds_path],
                capture_output=True,
                text=True,
                env=env,
                check=False,
            )
            self.assertEqual(res.returncode, 0, msg=res.stderr)
            self.assertIn("LabNet", res.stdout)
            self.assertIn("ALARMED", res.stdout)

            # Verify headless report export from replay (.md / .csv)
            md_path = os.path.join(tmp, "out.md")
            rep_res = subprocess.run(
                [ZDLINUX_BIN, "replay", zds_path, "--export", md_path],
                capture_output=True,
                text=True,
                env=env,
                check=False,
            )
            self.assertEqual(rep_res.returncode, 0, msg=rep_res.stderr)
            with open(md_path, "r", encoding="utf-8") as rfh:
                self.assertIn("LabNet", rfh.read())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--zd-linux", default="")
    parser.add_argument("--zd-sim", default="")
    args, remaining = parser.parse_known_args()

    global ZDSIM_BIN, ZDLINUX_BIN
    ZDSIM_BIN = args.zd_sim or resolve_default_bin("zd_sim")
    ZDLINUX_BIN = args.zd_linux or resolve_default_bin("zd-linux")
    unittest.main(argv=[sys.argv[0]] + remaining)


if __name__ == "__main__":
    main()
