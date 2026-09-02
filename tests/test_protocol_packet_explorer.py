import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "pseudonote_extended" / "protocol_packet_explorer.py").read_text(encoding="utf-8")
PLUGIN = (ROOT / "pseudonote_extended" / "plugin.py").read_text(encoding="utf-8")
MENU = (ROOT / "pseudonote_extended" / "ui" / "context_menu.py").read_text(encoding="utf-8")


class ProtocolPacketExplorerTests(unittest.TestCase):
    def test_recovers_network_roles_endpoints_and_handlers(self):
        for marker in ("scan_network_functions", "scan_endpoints", "scan_request_response_handlers", "receive", "transmit"):
            self.assertIn(marker, SOURCE)

    def test_recovers_command_ids_and_packet_fields(self):
        for marker in ("scan_command_dispatch", "calc_switch_cases", "Command ID candidate", "scan_packet_fields", "Packet field candidate"):
            self.assertIn(marker, SOURCE)

    def test_recovers_serialization_and_byte_order_routines(self):
        for marker in ("scan_serialization_routines", "ntoh", "hton", "protobuf", "msgpack", "serialize"):
            self.assertIn(marker, SOURCE.lower())

    def test_heuristic_structures_are_not_overclaimed(self):
        self.assertIn('"heuristic"', SOURCE)
        self.assertIn("requiring analyst validation", SOURCE)

    def test_correlates_protocol_artifacts_framing_and_sessions(self):
        for marker in ("scan_protocol_artifacts", "scan_protocol_framing", "scan_session_behavior", "bidirectional exchange"):
            self.assertIn(marker, SOURCE)

    def test_noise_controls_exclude_stack_fields_and_generic_handlers(self):
        self.assertIn("_STACK_BASE", SOURCE)
        self.assertIn("len(accesses) < 2", SOURCE)
        self.assertIn("if not signals", SOURCE)
        self.assertIn("_COMMON_CONTROL_VALUES", SOURCE)

    def test_endpoints_are_promoted_only_when_correlated_to_network_paths(self):
        self.assertIn("_network_related_functions", SOURCE)
        self.assertIn("validated endpoint referenced by network path", SOURCE)
        self.assertIn('confidence="low"', SOURCE)

    def test_supports_modern_and_cross_platform_protocol_stacks(self):
        for marker in ("websocket", "mqtt", "amqp", "grpc", "tls_read", "pr_read"):
            self.assertIn(marker, SOURCE.lower())

    def test_detects_ipc_c2_channels_and_beacon_timing(self):
        for marker in ("scan_ipc_channels", "CreateNamedPipe", "TransactNamedPipe", "scan_beacon_timing", "NtDelayExecution"):
            self.assertIn(marker, SOURCE)

    def test_action_is_registered_and_available_in_utilities(self):
        action = "pseudonote_extended:protocol_packet_explorer"
        self.assertGreaterEqual(PLUGIN.count(action), 2)
        self.assertIn(action, MENU)


if __name__ == "__main__":
    unittest.main()
