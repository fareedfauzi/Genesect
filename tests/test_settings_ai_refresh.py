import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
VIEW = (ROOT / "pseudonote_extended" / "view.py").read_text(encoding="utf-8-sig")
AI_CLIENT = (ROOT / "pseudonote_extended" / "ai_client.py").read_text(encoding="utf-8-sig")


class SettingsAIRuntimeRefreshTests(unittest.TestCase):
    def test_every_settings_dialog_save_rebuilds_the_shared_client(self):
        save_start = VIEW.index("        def on_save(self):")
        save_end = VIEW.index("    class PseudoNoteView", save_start)
        save_body = VIEW[save_start:save_end]
        self.assertIn("c.save()", save_body)
        self.assertIn("_ai_mod.reload_ai_client(c)", save_body)

    def test_reload_publishes_only_after_construction(self):
        start = AI_CLIENT.index("def reload_ai_client(config):")
        body = AI_CLIENT[start:]
        self.assertLess(
            body.index("replacement = SimpleAI(config)"),
            body.index("AI_CLIENT = replacement"),
        )

    def test_stale_self_assignment_was_removed(self):
        self.assertNotIn("_ai_mod.AI_CLIENT = _get_ai()", VIEW)


if __name__ == "__main__":
    unittest.main()
