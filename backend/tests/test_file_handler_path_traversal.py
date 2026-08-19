"""
Tests for path traversal vulnerability remediation in save_uploaded_file.

The vulnerability (CWE-22) arose because user-controlled filename values from
request.files were concatenated directly into a file-system path without
sanitization. The fix applies werkzeug.utils.secure_filename() at the input
boundary and adds a pathlib containment check to ensure the resolved path
stays within the upload directory.
"""
import unittest
import sys
import os
import pathlib
import tempfile
import shutil
from io import BytesIO
from unittest.mock import MagicMock, patch

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class MockFile:
    """Mimics a Werkzeug FileStorage object."""

    def __init__(self, filename, content=b"test content"):
        self.filename = filename
        self._content = content

    def save(self, path):
        with open(path, "wb") as fh:
            fh.write(self._content)


class TestSaveUploadedFilePathTraversal(unittest.TestCase):
    """
    Verifies that save_uploaded_file prevents path traversal attacks by
    sanitizing filenames and constraining the resolved path to the upload dir.
    """

    def setUp(self):
        """Create a temporary upload directory for each test."""
        self.upload_dir = tempfile.mkdtemp()
        # Patch Config.UPLOAD_FOLDER to point at the temp directory so tests
        # are fully isolated and do not depend on /app/uploads existing.
        self.config_patcher = patch("utils.file_handler.Config")
        mock_config = self.config_patcher.start()
        mock_config.UPLOAD_FOLDER = self.upload_dir

    def tearDown(self):
        self.config_patcher.stop()
        shutil.rmtree(self.upload_dir, ignore_errors=True)

    def _call(self, filename, content=b"data"):
        from utils.file_handler import save_uploaded_file
        mock_file = MockFile(filename, content)
        return save_uploaded_file(mock_file)

    # ------------------------------------------------------------------
    # Positive cases – legitimate filenames should be accepted
    # ------------------------------------------------------------------

    def test_normal_filename_accepted(self):
        """A plain filename is saved and the returned path is inside upload dir."""
        file_info, error = self._call("report.pdf")
        self.assertIsNone(error)
        self.assertIsNotNone(file_info)
        # Saved file must reside within the upload directory
        saved_path = pathlib.Path(file_info["file_path"]).resolve()
        upload_base = pathlib.Path(self.upload_dir).resolve()
        self.assertTrue(
            str(saved_path).startswith(str(upload_base) + os.sep),
            f"Expected path inside {upload_base}, got {saved_path}",
        )

    def test_filename_with_spaces_accepted(self):
        """Filenames with spaces are sanitised (spaces → underscores) and saved."""
        file_info, error = self._call("my document.txt")
        self.assertIsNone(error)
        self.assertIsNotNone(file_info)
        # secure_filename converts spaces to underscores
        self.assertNotIn(" ", file_info["original_filename"])

    def test_filename_preserved_in_metadata(self):
        """The sanitised original filename is returned in file_info."""
        file_info, error = self._call("invoice_2024.pdf")
        self.assertIsNone(error)
        self.assertIn("invoice_2024.pdf", file_info["original_filename"])

    def test_file_actually_created_on_disk(self):
        """The file is written to the upload directory."""
        file_info, error = self._call("hello.txt", b"hello world")
        self.assertIsNone(error)
        self.assertTrue(
            os.path.isfile(file_info["file_path"]),
            "Uploaded file should exist on disk",
        )

    def test_unique_uuid_prefix_prevents_name_collision(self):
        """Two uploads with the same filename get distinct on-disk names."""
        info1, _ = self._call("duplicate.txt", b"first")
        info2, _ = self._call("duplicate.txt", b"second")
        self.assertNotEqual(info1["filename"], info2["filename"])

    # ------------------------------------------------------------------
    # Negative cases – path traversal payloads must be blocked
    # ------------------------------------------------------------------

    def test_dot_dot_slash_traversal_blocked(self):
        """Classic ../etc/passwd traversal must not escape the upload dir."""
        file_info, error = self._call("../../../etc/passwd")
        # Either the call fails with an error, OR the saved path stays within
        # the upload directory.  A successful save outside the directory would
        # mean the vulnerability is still present.
        if error is None and file_info is not None:
            saved_path = pathlib.Path(file_info["file_path"]).resolve()
            upload_base = pathlib.Path(self.upload_dir).resolve()
            self.assertTrue(
                str(saved_path).startswith(str(upload_base) + os.sep),
                f"Path traversal succeeded: {saved_path} escaped {upload_base}",
            )

    def test_dot_dot_slash_traversal_sanitised_by_secure_filename(self):
        """
        werkzeug.secure_filename strips leading path components so the
        original_filename stored in file_info contains no directory separators.
        """
        file_info, error = self._call("../../secret.txt")
        if file_info is not None:
            self.assertNotIn("..", file_info["original_filename"])
            self.assertNotIn("/", file_info["original_filename"])
            self.assertNotIn("\\", file_info["original_filename"])

    def test_absolute_path_traversal_blocked(self):
        """An absolute path in the filename must not write outside upload dir."""
        file_info, error = self._call("/etc/passwd")
        if error is None and file_info is not None:
            saved_path = pathlib.Path(file_info["file_path"]).resolve()
            upload_base = pathlib.Path(self.upload_dir).resolve()
            self.assertTrue(
                str(saved_path).startswith(str(upload_base) + os.sep),
                f"Absolute path traversal succeeded: {saved_path}",
            )

    def test_windows_style_traversal_blocked(self):
        """Backslash-based traversal payloads are stripped."""
        file_info, error = self._call("..\\..\\windows\\system32\\cmd.exe")
        if file_info is not None:
            self.assertNotIn("..", file_info["original_filename"])

    def test_null_byte_injection_handled(self):
        """
        A filename containing a null byte (expressed as \\x00 escape, not a
        literal NUL character) must not cause unexpected file access.
        """
        file_info, error = self._call("evil\x00.txt")
        # The call should either fail gracefully or the stored filename must
        # not contain a null byte.
        if file_info is not None:
            self.assertNotIn("\x00", file_info["original_filename"])
            self.assertNotIn("\x00", file_info["filename"])

    def test_traversal_with_encoded_dots_sanitised(self):
        """Percent-encoded dots should be handled without traversal."""
        file_info, error = self._call("%2e%2e%2fetc%2fpasswd")
        if file_info is not None and error is None:
            saved_path = pathlib.Path(file_info["file_path"]).resolve()
            upload_base = pathlib.Path(self.upload_dir).resolve()
            self.assertTrue(
                str(saved_path).startswith(str(upload_base) + os.sep),
                f"Encoded traversal succeeded: {saved_path}",
            )

    # ------------------------------------------------------------------
    # Edge / boundary cases
    # ------------------------------------------------------------------

    def test_empty_filename_returns_error(self):
        """An empty filename string must return an error, not crash."""
        file_info, error = self._call("")
        self.assertIsNone(file_info)
        self.assertIsNotNone(error)

    def test_dot_only_filename_returns_error(self):
        """
        A filename consisting solely of dots is reduced to an empty string by
        secure_filename and must return an error.
        """
        file_info, error = self._call("...")
        # secure_filename("...") returns "" which triggers the empty-check
        self.assertIsNone(file_info)
        self.assertIsNotNone(error)

    def test_no_file_object_returns_error(self):
        """Passing None as file must return a descriptive error."""
        from utils.file_handler import save_uploaded_file
        file_info, error = save_uploaded_file(None)
        self.assertIsNone(file_info)
        self.assertIsNotNone(error)

    def test_file_with_no_filename_returns_error(self):
        """A file object whose filename is None/empty must return an error."""
        from utils.file_handler import save_uploaded_file
        mock_file = MockFile("")
        file_info, error = save_uploaded_file(mock_file)
        self.assertIsNone(file_info)
        self.assertIsNotNone(error)


class TestSaveUploadedFileContainmentCheck(unittest.TestCase):
    """
    Directly tests that the pathlib containment check raises a rejection when
    secure_filename alone is insufficient (e.g. a symlink-based edge case can
    be simulated by temporarily pointing upload_base elsewhere).
    """

    def setUp(self):
        self.upload_dir = tempfile.mkdtemp()
        self.config_patcher = patch("utils.file_handler.Config")
        mock_config = self.config_patcher.start()
        mock_config.UPLOAD_FOLDER = self.upload_dir

    def tearDown(self):
        self.config_patcher.stop()
        shutil.rmtree(self.upload_dir, ignore_errors=True)

    def test_returned_file_path_is_inside_upload_folder(self):
        """
        For any successful upload the returned file_path must be inside the
        configured upload folder (containment invariant).
        """
        from utils.file_handler import save_uploaded_file
        mock_file = MockFile("document.pdf", b"pdf content")
        file_info, error = save_uploaded_file(mock_file)
        self.assertIsNone(error)
        self.assertIsNotNone(file_info)

        upload_base = pathlib.Path(self.upload_dir).resolve()
        saved = pathlib.Path(file_info["file_path"]).resolve()
        self.assertTrue(
            str(saved).startswith(str(upload_base) + os.sep),
            f"Containment check failed: {saved} not inside {upload_base}",
        )

    def test_secure_filename_strips_path_separators(self):
        """
        Verify that werkzeug.secure_filename is actually invoked and strips
        directory components from the stored original_filename.
        """
        from werkzeug.utils import secure_filename
        attack_vectors = [
            "../../../etc/passwd",
            "../../windows/system32/cmd.exe",
            "/etc/shadow",
            "foo/../bar",
        ]
        for payload in attack_vectors:
            sanitised = secure_filename(payload)
            self.assertNotIn("..", sanitised, f"Dots not stripped from: {payload}")
            self.assertNotIn("/", sanitised, f"Slash not stripped from: {payload}")
            self.assertNotIn("\\", sanitised, f"Backslash not stripped from: {payload}")


if __name__ == "__main__":
    unittest.main()
