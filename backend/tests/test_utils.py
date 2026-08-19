"""
Basic tests for utility functions
"""
import unittest
import sys
import os
import tempfile
import shutil
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.datetime_utils import get_utc_now, format_utc_datetime, get_utc_timestamp
from utils.file_handler import process_pickle_file, extract_file_metadata, allowed_file


class TestDateTimeUtils(unittest.TestCase):
    """Test datetime utility functions"""

    def test_get_utc_now(self):
        """Test get_utc_now returns datetime"""
        result = get_utc_now()
        self.assertIsInstance(result, datetime)

    def test_get_utc_timestamp(self):
        """Test get_utc_timestamp returns float"""
        result = get_utc_timestamp()
        self.assertIsInstance(result, float)
        self.assertGreater(result, 0)

    def test_format_utc_datetime_default(self):
        """Test format_utc_datetime with default (current time)"""
        result = format_utc_datetime()
        self.assertIsInstance(result, str)
        # ISO format should contain 'T'
        self.assertIn('T', result)

    def test_format_utc_datetime_with_value(self):
        """Test format_utc_datetime with specific datetime"""
        dt = datetime(2023, 12, 25, 15, 30, 45)
        result = format_utc_datetime(dt)
        self.assertIsInstance(result, str)
        self.assertIn('2023', result)
        self.assertIn('12', result)
        self.assertIn('25', result)


class TestStringUtils(unittest.TestCase):
    """Test basic string utilities"""

    def test_string_truncation_logic(self):
        """Test basic truncation logic"""
        text = "This is a very long text that should be truncated"
        max_length = 20

        if len(text) > max_length:
            truncated = text[:max_length] + '...'
        else:
            truncated = text

        self.assertEqual(len(truncated), 23)  # 20 + "..."
        self.assertTrue(truncated.endswith('...'))

    def test_file_size_calculation(self):
        """Test file size calculation logic"""
        # Test bytes
        size = 500
        self.assertLess(size, 1024)

        # Test KB
        size_kb = 1500
        kb_value = size_kb / 1024.0
        self.assertGreater(kb_value, 1.0)
        self.assertLess(kb_value, 1024.0)


class TestProcessPickleFileSecurity(unittest.TestCase):
    """
    Tests for the process_pickle_file remediation.

    CWE-502 (Deserialization of Untrusted Data): pickle.load() on an
    attacker-supplied file allows arbitrary Python code execution.  The fix
    removes pickle deserialization entirely so no payload can ever be executed.
    """

    def setUp(self):
        """Create a temporary directory for test files."""
        self.tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        """Remove the temporary directory and its contents."""
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    # ------------------------------------------------------------------
    # Security: pickle deserialization must be refused unconditionally
    # ------------------------------------------------------------------

    def test_process_pickle_file_returns_error_dict(self):
        """process_pickle_file must return an error dict, never deserialize."""
        # Create a benign (but real) pickle file with innocent data so the
        # test does not depend on pickle being importable by the test runner.
        import pickle
        pkl_path = os.path.join(self.tmpdir, 'data.pkl')
        with open(pkl_path, 'wb') as fh:
            pickle.dump({'key': 'value'}, fh)

        result = process_pickle_file(pkl_path)

        self.assertIsInstance(result, dict,
            "process_pickle_file must return a dict")
        self.assertIn('error', result,
            "result must contain an 'error' key — pickle processing refused")

    def test_process_pickle_file_error_message_is_descriptive(self):
        """The error message should indicate that pickle is not supported."""
        import pickle
        pkl_path = os.path.join(self.tmpdir, 'data.pkl')
        with open(pkl_path, 'wb') as fh:
            pickle.dump([1, 2, 3], fh)

        result = process_pickle_file(pkl_path)

        error_msg = result.get('error', '').lower()
        self.assertTrue(
            'pickle' in error_msg or 'not supported' in error_msg
                or 'security' in error_msg,
            f"Error message should mention pickle/security, got: {result['error']!r}"
        )

    def test_process_pickle_file_with_malicious_payload_is_blocked(self):
        """
        A pickle payload that would execute os.system() must never run.

        We craft a pickle payload using the REDUCE opcode (the same mechanism
        real exploits use) and confirm that process_pickle_file does NOT
        execute it.  We detect execution via a sentinel file that the payload
        would create if executed.
        """
        import pickle
        import struct

        sentinel_path = os.path.join(self.tmpdir, 'pwned.txt')

        # Build a malicious pickle manually using the __reduce__ protocol.
        class _Exploit:
            def __reduce__(self):
                # If deserialized, this writes the sentinel file.
                return (open, (sentinel_path, 'w'))

        pkl_path = os.path.join(self.tmpdir, 'malicious.pkl')
        with open(pkl_path, 'wb') as fh:
            pickle.dump(_Exploit(), fh)

        # Call the function under test — it must NOT execute the payload.
        process_pickle_file(pkl_path)

        self.assertFalse(
            os.path.exists(sentinel_path),
            "Malicious pickle payload was executed — deserialization sink is still active"
        )

    def test_process_pickle_file_does_not_import_or_use_pickle_module(self):
        """
        The file_handler module must not import pickle at all.  Importing it
        is a prerequisite for calling pickle.load; its absence is a strong
        indicator that the sink has been removed.
        """
        import importlib
        import utils.file_handler as fh_module

        # Reload to get the current module state (avoids cached imports).
        importlib.reload(fh_module)

        self.assertFalse(
            hasattr(fh_module, 'pickle'),
            "utils.file_handler must not import the 'pickle' module after remediation"
        )

    def test_process_pickle_file_nonexistent_path_returns_error(self):
        """process_pickle_file must handle a nonexistent path gracefully."""
        result = process_pickle_file('/nonexistent/path/file.pkl')

        # The function must return a dict; with the fix it never even opens
        # the file, so the result is the fixed error regardless of path.
        self.assertIsInstance(result, dict)
        self.assertIn('error', result)

    def test_process_pickle_file_empty_file_returns_error(self):
        """process_pickle_file must handle an empty file without executing code."""
        empty_pkl = os.path.join(self.tmpdir, 'empty.pkl')
        open(empty_pkl, 'wb').close()

        result = process_pickle_file(empty_pkl)

        self.assertIsInstance(result, dict)
        self.assertIn('error', result)

    # ------------------------------------------------------------------
    # Integration: extract_file_metadata must propagate the refusal
    # ------------------------------------------------------------------

    def test_extract_file_metadata_pickle_extension_refused(self):
        """
        extract_file_metadata must not deserialize .pkl files.
        It should include a 'pickle_data' key whose value signals an error.
        """
        import pickle
        pkl_path = os.path.join(self.tmpdir, 'test.pkl')
        with open(pkl_path, 'wb') as fh:
            pickle.dump({'x': 1}, fh)

        metadata = extract_file_metadata(pkl_path)

        self.assertIn('pickle_data', metadata,
            "extract_file_metadata should include 'pickle_data' for .pkl files")
        self.assertIn('error', metadata['pickle_data'],
            "'pickle_data' should carry an error, not deserialized content")

    def test_extract_file_metadata_dot_pickle_extension_refused(self):
        """
        extract_file_metadata must refuse .pickle files as well as .pkl.
        """
        import pickle
        pkl_path = os.path.join(self.tmpdir, 'test.pickle')
        with open(pkl_path, 'wb') as fh:
            pickle.dump({'y': 2}, fh)

        metadata = extract_file_metadata(pkl_path)

        self.assertIn('pickle_data', metadata)
        self.assertIn('error', metadata['pickle_data'])

    def test_extract_file_metadata_contains_file_stats(self):
        """
        extract_file_metadata must still return standard file stats even for
        pickle files (size, created, modified) — the security fix must not
        regress the stat-collection path.
        """
        import pickle
        pkl_path = os.path.join(self.tmpdir, 'stats.pkl')
        with open(pkl_path, 'wb') as fh:
            pickle.dump('hello', fh)

        metadata = extract_file_metadata(pkl_path)

        self.assertIn('size', metadata)
        self.assertIn('created', metadata)
        self.assertIn('modified', metadata)

    # ------------------------------------------------------------------
    # Regression: allowed_file helper is unaffected
    # ------------------------------------------------------------------

    def test_allowed_file_is_unchanged(self):
        """
        The allowed_file helper must continue to work correctly after the
        remediation — it was not part of the fix.
        """
        # txt is in ALLOWED_EXTENSIONS per config.py
        self.assertTrue(allowed_file('report.txt'))
        # No extension → not allowed
        self.assertFalse(allowed_file('noextension'))


if __name__ == '__main__':
    unittest.main()
