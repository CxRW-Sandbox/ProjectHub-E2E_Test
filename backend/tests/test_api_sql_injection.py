"""
Security tests for SQL injection prevention in /api/v1/users endpoint.

These tests verify that the get_users endpoint correctly uses parameterized
queries instead of string-formatted SQL, preventing SQL injection attacks
(CWE-89).
"""
import pytest
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import db, User


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_user(db_session, username, email, role='team_member'):
    """Create a user directly in the test database."""
    user = User(username=username, email=email, role=role)
    user.set_password('testpass123')
    db_session.add(user)
    db_session.commit()
    return user


# ---------------------------------------------------------------------------
# Functional tests – verify that legitimate searches work correctly
# ---------------------------------------------------------------------------

class TestGetUsersSearchFunctionality:
    """Verify that the search feature works correctly after the parameterization fix."""

    def test_get_users_no_search_returns_all(self, client, db_session):
        """Without a search parameter all users are returned."""
        _create_user(db_session, 'alice', 'alice@example.com')
        _create_user(db_session, 'bob', 'bob@example.com')

        response = client.get('/api/v1/users')
        assert response.status_code == 200

        data = response.get_json()
        assert 'users' in data
        assert data['count'] >= 2

    def test_get_users_search_by_username(self, client, db_session):
        """Search term matching a username returns the correct user."""
        _create_user(db_session, 'charlie', 'charlie@example.com')
        _create_user(db_session, 'dave', 'dave@example.com')

        response = client.get('/api/v1/users?search=charlie')
        assert response.status_code == 200

        data = response.get_json()
        usernames = [u['username'] for u in data['users']]
        assert 'charlie' in usernames
        assert 'dave' not in usernames

    def test_get_users_search_by_email(self, client, db_session):
        """Search term matching an email domain returns matching users."""
        _create_user(db_session, 'eve', 'eve@corp.com')
        _create_user(db_session, 'frank', 'frank@personal.net')

        response = client.get('/api/v1/users?search=corp.com')
        assert response.status_code == 200

        data = response.get_json()
        usernames = [u['username'] for u in data['users']]
        assert 'eve' in usernames
        assert 'frank' not in usernames

    def test_get_users_search_partial_match(self, client, db_session):
        """Partial search term matches substrings in username or email."""
        _create_user(db_session, 'grace_admin', 'grace@example.com')

        response = client.get('/api/v1/users?search=grace')
        assert response.status_code == 200

        data = response.get_json()
        usernames = [u['username'] for u in data['users']]
        assert 'grace_admin' in usernames

    def test_get_users_search_no_match_returns_empty(self, client, db_session):
        """A search term that matches nothing returns an empty list."""
        _create_user(db_session, 'henry', 'henry@example.com')

        response = client.get('/api/v1/users?search=zzznomatch')
        assert response.status_code == 200

        data = response.get_json()
        assert data['count'] == 0
        assert data['users'] == []

    def test_get_users_empty_search_returns_all(self, client, db_session):
        """An explicitly empty search string returns all users (ORM path)."""
        _create_user(db_session, 'irene', 'irene@example.com')

        response = client.get('/api/v1/users?search=')
        assert response.status_code == 200

        data = response.get_json()
        assert data['count'] >= 1

    def test_response_contains_count_and_request_id(self, client, db_session):
        """Response envelope always includes 'count' and 'request_id'."""
        response = client.get('/api/v1/users')
        assert response.status_code == 200

        data = response.get_json()
        assert 'count' in data
        assert 'request_id' in data


# ---------------------------------------------------------------------------
# Security tests – SQL injection payloads must NOT alter query behaviour
# ---------------------------------------------------------------------------

class TestGetUsersSQLInjectionPrevention:
    """
    Verify that SQL injection payloads in the 'search' parameter are treated
    as literal strings and do not affect the query's structure or results.

    With the parameterized fix each payload is bound as a LIKE pattern value,
    so none of these should raise a database error or return unexpected rows.
    """

    def test_sqli_or_true_tautology(self, client, db_session):
        """
        Classic OR-1=1 tautology must NOT return all rows when no real match exists.

        Without parameterization  '%' OR '1'='1  would match every row.
        With parameterization the entire string is the LIKE pattern, so
        it can only match a username/email that literally contains that text.
        """
        _create_user(db_session, 'jack', 'jack@example.com')

        # Payload: ' OR '1'='1
        payload = "' OR '1'='1"
        response = client.get(f'/api/v1/users?search={payload}')
        assert response.status_code == 200

        data = response.get_json()
        # 'jack' should NOT be returned – the payload is not part of his username/email
        usernames = [u['username'] for u in data['users']]
        assert 'jack' not in usernames

    def test_sqli_single_quote_does_not_error(self, client, db_session):
        """A bare single-quote in the search parameter must not raise a DB error."""
        response = client.get("/api/v1/users?search='")
        assert response.status_code == 200

    def test_sqli_double_quote_does_not_error(self, client, db_session):
        """A double-quote in the search parameter must not raise a DB error."""
        response = client.get('/api/v1/users?search="')
        assert response.status_code == 200

    def test_sqli_semicolon_does_not_execute_second_statement(self, client, db_session):
        """
        A semicolon followed by DROP/DELETE must not cause any error or
        affect the database.
        """
        _create_user(db_session, 'karen', 'karen@example.com')

        payload = "x'; DROP TABLE users; --"
        response = client.get(f'/api/v1/users?search={payload}')
        # Must not crash
        assert response.status_code == 200

        # The users table must still exist and contain 'karen'
        get_all = client.get('/api/v1/users')
        assert get_all.status_code == 200
        usernames = [u['username'] for u in get_all.get_json()['users']]
        assert 'karen' in usernames

    def test_sqli_comment_sequence_does_not_alter_results(self, client, db_session):
        """SQL comment sequences (-- and #) in the search must be treated literally."""
        _create_user(db_session, 'leo', 'leo@example.com')

        for payload in ["--", "#", "' --", "admin'--"]:
            response = client.get(f'/api/v1/users?search={payload}')
            assert response.status_code == 200, f"Payload '{payload}' caused an error"
            data = response.get_json()
            usernames = [u['username'] for u in data['users']]
            # 'leo' must not appear – none of these are substrings of 'leo' or his email
            assert 'leo' not in usernames, (
                f"Payload '{payload}' unexpectedly returned user 'leo'"
            )

    def test_sqli_union_select_does_not_return_extra_rows(self, client, db_session):
        """
        A UNION SELECT payload must not inject additional rows into the result.
        The parameterized LIKE treats the whole string as a literal value.
        """
        _create_user(db_session, 'mike', 'mike@example.com')

        payload = "x' UNION SELECT 1,2,3,4,5,6,7,8,9 --"
        response = client.get(f'/api/v1/users?search={payload}')
        assert response.status_code == 200

        data = response.get_json()
        # No rows should match the literal LIKE pattern containing UNION SELECT
        assert data['count'] == 0

    def test_sqli_wildcard_percent_treated_as_literal_pattern(self, client, db_session):
        """
        A bare '%' is a valid LIKE wildcard, but when the *entire* search value
        is '%' (passed as the bound parameter) it becomes '%%' in the pattern,
        i.e. %{search}% with search='%' → '%%%' which still matches everything.
        This test documents the current behaviour (LIKE wildcard is intentional)
        and ensures no SQL error is raised.
        """
        _create_user(db_session, 'nina', 'nina@example.com')

        response = client.get('/api/v1/users?search=%25')  # URL-encoded '%'
        assert response.status_code == 200
        # Just verify no server error — wildcard behaviour is acceptable

    def test_sqli_null_byte_does_not_error(self, client, db_session):
        """
        A null byte (%00) in the search parameter must not cause a server error.
        Expressed as the URL-encoded form so no raw control byte is embedded in
        this source file.
        """
        response = client.get('/api/v1/users?search=%00')
        # Must not crash with 500
        assert response.status_code in (200, 400)

    def test_sqli_backslash_does_not_error(self, client, db_session):
        """Backslash sequences in the search must not cause a server error."""
        response = client.get("/api/v1/users?search=\\")
        assert response.status_code == 200

    def test_sqli_special_chars_combo_does_not_error(self, client, db_session):
        """A combination of special characters must not cause a server error."""
        payload = "'; SELECT * FROM users WHERE ''='"
        response = client.get(f'/api/v1/users?search={payload}')
        assert response.status_code == 200

    def test_sqli_encoded_quote_does_not_error(self, client, db_session):
        """URL-encoded single quote (%27) must not cause a server error."""
        response = client.get('/api/v1/users?search=%27')
        assert response.status_code == 200
