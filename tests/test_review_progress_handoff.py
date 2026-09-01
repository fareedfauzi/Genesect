import pathlib
import unittest


SOURCE = (pathlib.Path(__file__).parents[1] / "pseudonote_extended" / "handlers.py").read_text(encoding="utf-8")


class ReviewProgressHandoffTests(unittest.TestCase):
    def test_variable_review_hides_generation_overlay_first(self):
        section = SOURCE[SOURCE.index("def wrapped_cb(response, **kwargs):", SOURCE.index("class RenameVariablesHandler")):SOURCE.index("total_chars = [0]", SOURCE.index("class RenameVariablesHandler"))]
        self.assertLess(section.index("hide_ai_progress()"), section.index("_pn_rename_callback("))

    def test_function_rename_reviews_hide_generation_overlay_first(self):
        for marker in ("class RenameFunctionHandler", "class RenameMalwareFunctionHandler"):
            start = SOURCE.index(marker)
            section = SOURCE[SOURCE.index("def callback(response, **kwargs):", start):SOURCE.index("total_chars = [0]", start)]
            self.assertLess(section.index("hide_ai_progress()"), section.index("_review_function_rename("))

    def test_comment_review_hides_generation_overlay_first(self):
        start = SOURCE.index("class CommentHandler")
        section = SOURCE[SOURCE.index("def wrapped_cb(response, **kwargs):", start):SOURCE.index("total_chars = [0]", start)]
        self.assertLess(section.index("hide_ai_progress()"), section.index("_pn_comment_callback("))


if __name__ == "__main__":
    unittest.main()
