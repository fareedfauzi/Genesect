import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "syscall_kernel_mapper.py").read_text(encoding="utf-8")
PLUGIN = (ROOT / "pseudonote_extended" / "plugin.py").read_text(encoding="utf-8")
MENU = (ROOT / "pseudonote_extended" / "ui" / "context_menu.py").read_text(encoding="utf-8")


class SyscallKernelMapperTests(unittest.TestCase):
    def test_recovers_direct_syscalls_and_numbers_cross_architecture(self):
        for marker in ("syscall", "sysenter", "svc", "swi", "ecall", "_syscall_number", "e?ax", "x8", "a7"):
            self.assertIn(marker, SOURCE)

    def test_maps_native_interfaces_ioctls_devices_and_callbacks(self):
        for marker in ("scan_native_interfaces", "decode_ioctl", "scan_device_and_ioctls", "scan_device_paths", "scan_kernel_callbacks"):
            self.assertIn(marker, SOURCE)

    def test_maps_driver_dispatch_and_trust_boundaries(self):
        for marker in ("scan_trust_boundaries", "scan_driver_dispatch_tables", "MajorFunction", "ProbeForRead".lower(), "copy_from_user", "Driver dispatch", "User/kernel trust boundary"):
            self.assertIn(marker.lower(), SOURCE.lower())

    def test_has_filter_navigation_details_copy_and_csv(self):
        for marker in ("apply_filter", "navigate_selected", "Kernel-interface evidence", "Copy Selected", "Export CSV"):
            self.assertIn(marker, SOURCE)

    def test_action_is_registered_and_available_in_utilities(self):
        action = "pseudonote_extended:syscall_kernel_mapper"
        self.assertGreaterEqual(PLUGIN.count(action), 2)
        self.assertIn(action, MENU)


if __name__ == "__main__":
    unittest.main()
