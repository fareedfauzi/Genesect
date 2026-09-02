import importlib.util
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


menu = load_module("pn_context_menu_icons_test", ROOT / "pseudonote_extended" / "ui" / "context_menu.py")
icons = load_module("pn_icons_test", ROOT / "pseudonote_extended" / "ui" / "icons.py")


class MenuIconTests(unittest.TestCase):
    def test_every_context_action_has_action_specific_icon(self):
        actions = {
            action.rsplit(":", 1)[-1]
            for pseudocode in (False, True)
            for _, rows in menu.menu_groups(pseudocode)
            for action in rows if action != "-"
        }
        self.assertEqual(actions - set(icons.ACTION_FAMILIES), set())

    def test_generated_action_icons_are_distinct(self):
        rendered = []
        for variant, (action, family) in enumerate(icons.ACTION_FAMILIES.items(), 1):
            rendered.append(icons._svg(
                icons.COLORS[family], icons.GLYPHS[icons.ACTION_GLYPHS[action]], variant
            ))
        self.assertEqual(len(rendered), len(set(rendered)))

    def test_every_action_has_a_semantic_primary_glyph(self):
        self.assertEqual(set(icons.ACTION_FAMILIES), set(icons.ACTION_GLYPHS))
        self.assertTrue(set(icons.ACTION_GLYPHS.values()) <= set(icons.GLYPHS))
        # The old implementation exposed only nine category symbols. The menu
        # should now have a broad, visibly distinct feature vocabulary.
        self.assertGreaterEqual(len(set(icons.ACTION_GLYPHS.values())), 35)
        self.assertEqual(len(icons.ACTION_GLYPHS), len(set(icons.ACTION_GLYPHS.values())))

    def test_icons_use_minimalist_high_dpi_vector_rendering(self):
        rendered = icons._svg(icons.COLORS["analysis"], icons.GLYPHS["agent"], 23).decode("utf-8")
        self.assertIn('width="16" height="16"', rendered)
        self.assertIn('shape-rendering="geometricPrecision"', rendered)
        self.assertIn('data-variant="23"', rendered)
        self.assertIn('fill="#000000"', rendered)
        self.assertEqual(rendered.count('<path'), 1)

    def test_every_non_brand_action_uses_minimalist_design(self):
        for variant, (action, family) in enumerate(icons.ACTION_FAMILIES.items(), 1):
            if icons._brand_svg(action):
                continue
            rendered = icons._svg(
                icons.COLORS[family], icons.GLYPHS[icons.ACTION_GLYPHS[action]], variant
            ).decode("utf-8")
            self.assertIn('fill="#000000"', rendered, action)

    def test_registered_actions_request_their_specific_icons(self):
        plugin_source = (ROOT / "pseudonote_extended" / "plugin.py").read_text(encoding="utf-8-sig")
        for action in icons.ACTION_FAMILIES:
            self.assertIn(f'icon("{action}"', plugin_source, action)

    def test_external_pivots_use_embedded_brand_marks(self):
        for action in (
            "search_bytes_vt", "search_str_vt", "search_str_google",
            "search_str_github", "search_str_msdn",
            "search_bytes_cyberchef", "search_str_cyberchef",
        ):
            rendered = icons._brand_svg(action)
            self.assertIsNotNone(rendered, action)
            self.assertIn(b'<svg', rendered)
        self.assertIn(b'#4285F4', icons._brand_svg("search_str_google"))
        self.assertIn(b'#181717', icons._brand_svg("search_str_github"))
        self.assertIn(b'#394EFF', icons._brand_svg("search_str_vt"))
        self.assertIn(b'#F08A24', icons._brand_svg("search_str_cyberchef"))


if __name__ == "__main__":
    unittest.main()
