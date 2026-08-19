"""
Security tests for SQL injection prevention in /api/messages/search endpoint.

These tests verify that the search_messages endpoint correctly uses parameterized
queries instead of string-formatted SQL, preventing SQL injection attacks
(CWE-89).

The taint flow that was remediated:
  SOURCE: request.args.get('q')  → line 127 of routes/messages.py
  SINK:   db.session.execute(text(sql_query))  → line 134 of routes/messages.py

The fix replaces the f-string interpolation with a SQLAlchemy named-parameter
binding so the database driver handles quoting and user input never alters the
query structure.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import db, User, Message


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


def _create_message(db_session, sender, receiver, subject, content):
    """Create a message directly in the test database."""
    message = Message(
        sender_id=sender.id,
        receiver_id=receiver.id,
        subject=subject,
        content=content,
    )
    db_session.add(message)
    db_session.commit()
    return message


def _auth_headers(app, user):
    """Return a Bearer-token Authorization header dict for the given user."""
    with app.app_context():
        from auth import generate_token
        token = generate_token(user.id, user.username)
        return {'Authorization': f'Bearer {token}'}


# ---------------------------------------------------------------------------
# Functional tests – verify that legitimate searches work correctly
# ---------------------------------------------------------------------------

class TestSearchMessagesFunctionality:
    """Verify that the search feature works correctly after the parameterization fix."""

    def test_search_requires_auth(self, client):
        """Unauthenticated requests must be rejected with 401."""
        response = client.get('/api/messages/search?q=hello')
        assert response.status_code == 401

    def test_search_missing_query_returns_400(self, app, client, db_session):
        """A request without the 'q' parameter must return 400."""
        sender = _create_user(db_session, 'sender1', 'sender1@example.com')
        headers = _auth_headers(app, sender)

        response = client.get('/api/messages/search', headers=headers)
        assert response.status_code == 400

    def test_search_empty_query_returns_400(self, app, client, db_session):
        """An explicitly empty 'q' parameter must return 400."""
        sender = _create_user(db_session, 'sender2', 'sender2@example.com')
        headers = _auth_headers(app, sender)

        response = client.get('/api/messages/search?q=', headers=headers)
        assert response.status_code == 400

    def test_search_by_content_returns_matching_message(self, app, client, db_session):
        """A search term matching message content must return that message."""
        sender = _create_user(db_session, 'alice', 'alice@example.com')
        receiver = _create_user(db_session, 'bob', 'bob@example.com')
        _create_message(db_session, sender, receiver, 'Hello', 'unique_content_xyz')
        headers = _auth_headers(app, sender)

        response = client.get('/api/messages/search?q=unique_content_xyz', headers=headers)
        assert response.status_code == 200

        data = response.get_json()
        assert 'results' in data
        assert len(data['results']) == 1
        assert data['results'][0]['content'] == 'unique_content_xyz'

    def test_search_by_subject_returns_matching_message(self, app, client, db_session):
        """A search term matching message subject must return that message."""
        sender = _create_user(db_session, 'carol', 'carol@example.com')
        receiver = _create_user(db_session, 'dan', 'dan@example.com')
        _create_message(db_session, sender, receiver, 'unique_subject_abc', 'Some content')
        headers = _auth_headers(app, sender)

        response = client.get('/api/messages/search?q=unique_subject_abc', headers=headers)
        assert response.status_code == 200

        data = response.get_json()
        assert 'results' in data
        assert len(data['results']) == 1
        assert data['results'][0]['subject'] == 'unique_subject_abc'

    def test_search_partial_match(self, app, client, db_session):
        """Partial search term matches substrings in content or subject."""
        sender = _create_user(db_session, 'eve_s', 'eve_s@example.com')
        receiver = _create_user(db_session, 'frank_s', 'frank_s@example.com')
        _create_message(db_session, sender, receiver, 'Report Q3', 'See attached report')
        headers = _auth_headers(app, sender)

        response = client.get('/api/messages/search?q=Q3', headers=headers)
        assert response.status_code == 200

        data = response.get_json()
        subjects = [r['subject'] for r in data['results']]
        assert 'Report Q3' in subjects

    def test_search_no_match_returns_empty_results(self, app, client, db_session):
        """A search term that matches nothing returns an empty results list."""
        sender = _create_user(db_session, 'grace_s', 'grace_s@example.com')
        receiver = _create_user(db_session, 'henry_s', 'henry_s@example.com')
        _create_message(db_session, sender, receiver, 'Normal subject', 'Normal content')
        headers = _auth_headers(app, sender)

        response = client.get('/api/messages/search?q=zzznomatch', headers=headers)
        assert response.status_code == 200

        data = response.get_json()
        assert data['results'] == []

    def test_response_envelope_contains_query_and_results(self, app, client, db_session):
        """Response body must include both 'query' and 'results' keys."""
        sender = _create_user(db_session, 'ivan_s', 'ivan_s@example.com')
        receiver = _create_user(db_session, 'judy_s', 'judy_s@example.com')
        _create_message(db_session, sender, receiver, 'Test', 'Hello world')
        headers = _auth_headers(app, sender)

        response = client.get('/api/messages/search?q=Hello', headers=headers)
        assert response.status_code == 200

        data = response.get_json()
        assert 'query' in data
        assert 'results' in data
        assert data['query'] == 'Hello'


# ---------------------------------------------------------------------------
# Security tests – SQL injection payloads must NOT alter query behaviour
# ---------------------------------------------------------------------------

class TestSearchMessagesSQLInjectionPrevention:
    """
    Verify that SQL injection payloads in the 'q' parameter are treated as
    literal strings and do not affect the query's structure or results.

    With the parameterized fix each payload is bound as a named :pattern
    parameter, so none of these should raise a database error or return
    unexpected rows.
    """

    def test_sqli_single_quote_does_not_error(self, app, client, db_session):
        """A bare single-quote must not raise a database error (500)."""
        sender = _create_user(db_session, 'sqli_u1', 'sqli_u1@example.com')
        headers = _auth_headers(app, sender)

        response = client.get("/api/messages/search?q='", headers=headers)
        assert response.status_code == 200

    def test_sqli_double_quote_does_not_error(self, app, client, db_session):
        """A double-quote must not raise a database error."""
        sender = _create_user(db_session, 'sqli_u2', 'sqli_u2@example.com')
        headers = _auth_headers(app, sender)

        response = client.get('/api/messages/search?q="', headers=headers)
        assert response.status_code == 200

    def test_sqli_or_tautology_does_not_return_all_rows(self, app, client, db_session):
        """
        Classic OR-1=1 tautology must NOT return all rows when no real match
        exists.

        Without parameterization `' OR '1'='1` would turn the LIKE condition
        into a tautology matching every row.  With the named-parameter binding
        the entire payload is the LIKE value, so it can only match a message
        whose content/subject literally contains that text.
        """
        sender = _create_user(db_session, 'sqli_u3', 'sqli_u3@example.com')
        receiver = _create_user(db_session, 'sqli_u3r', 'sqli_u3r@example.com')
        _create_message(db_session, sender, receiver, 'Confidential', 'Secret data')
        headers = _auth_headers(app, sender)

        # Payload: ' OR '1'='1
        payload = "' OR '1'='1"
        response = client.get(f'/api/messages/search?q={payload}', headers=headers)
        assert response.status_code == 200

        data = response.get_json()
        # 'Secret data' must NOT appear — the payload is not a substring of it
        contents = [r['content'] for r in data['results']]
        assert 'Secret data' not in contents

    def test_sqli_semicolon_drop_table_does_not_destroy_data(self, app, client, db_session):
        """
        A semicolon + DROP TABLE payload must not cause any error or delete
        rows from the database.
        """
        sender = _create_user(db_session, 'sqli_u4', 'sqli_u4@example.com')
        receiver = _create_user(db_session, 'sqli_u4r', 'sqli_u4r@example.com')
        _create_message(db_session, sender, receiver, 'Persist', 'Should survive injection')
        headers = _auth_headers(app, sender)

        payload = "x'; DROP TABLE messages; --"
        response = client.get(f'/api/messages/search?q={payload}', headers=headers)
        # Must not crash
        assert response.status_code == 200

        # The messages table must still exist and the message must still be there
        surviving = Message.query.filter_by(content='Should survive injection').first()
        assert surviving is not None

    def test_sqli_comment_sequences_do_not_alter_results(self, app, client, db_session):
        """SQL comment sequences (-- and #) must be treated as literal text."""
        sender = _create_user(db_session, 'sqli_u5', 'sqli_u5@example.com')
        receiver = _create_user(db_session, 'sqli_u5r', 'sqli_u5r@example.com')
        _create_message(db_session, sender, receiver, 'Private', 'Private content')
        headers = _auth_headers(app, sender)

        for payload in ["--", "#", "' --", "admin'--"]:
            response = client.get(
                f'/api/messages/search?q={payload}', headers=headers
            )
            assert response.status_code == 200, (
                f"Payload '{payload}' caused a server error"
            )
            data = response.get_json()
            contents = [r['content'] for r in data['results']]
            # 'Private content' must not be returned by any of these payloads
            assert 'Private content' not in contents, (
                f"Payload '{payload}' unexpectedly returned 'Private content'"
            )

    def test_sqli_union_select_does_not_inject_extra_rows(self, app, client, db_session):
        """
        A UNION SELECT payload must not inject additional rows into the result.
        With the named-parameter binding the whole string is a LIKE value so
        no UNION is appended to the query.
        """
        sender = _create_user(db_session, 'sqli_u6', 'sqli_u6@example.com')
        headers = _auth_headers(app, sender)

        payload = "x' UNION SELECT 1,2,3,4,5,6,7 --"
        response = client.get(f'/api/messages/search?q={payload}', headers=headers)
        assert response.status_code == 200

        data = response.get_json()
        # No rows should match the literal LIKE pattern containing UNION SELECT
        assert data['results'] == []

    def test_sqli_backslash_does_not_error(self, app, client, db_session):
        """Backslash sequences must not cause a server error."""
        sender = _create_user(db_session, 'sqli_u7', 'sqli_u7@example.com')
        headers = _auth_headers(app, sender)

        response = client.get("/api/messages/search?q=\\", headers=headers)
        assert response.status_code == 200

    def test_sqli_encoded_quote_does_not_error(self, app, client, db_session):
        """URL-encoded single quote (%27) must not cause a server error."""
        sender = _create_user(db_session, 'sqli_u8', 'sqli_u8@example.com')
        headers = _auth_headers(app, sender)

        response = client.get('/api/messages/search?q=%27', headers=headers)
        assert response.status_code == 200

    def test_sqli_special_chars_combo_does_not_error(self, app, client, db_session):
        """A combination of special characters must not cause a server error."""
        sender = _create_user(db_session, 'sqli_u9', 'sqli_u9@example.com')
        headers = _auth_headers(app, sender)

        payload = "'; SELECT * FROM messages WHERE ''='"
        response = client.get(f'/api/messages/search?q={payload}', headers=headers)
        assert response.status_code == 200

    def test_sqli_null_byte_does_not_cause_500(self, app, client, db_session):
        """
        A null byte (%00) in the search parameter must not cause a 500.
        Expressed as the URL-encoded form (%00) so no raw control byte is
        embedded in this source file.
        """
        sender = _create_user(db_session, 'sqli_u10', 'sqli_u10@example.com')
        headers = _auth_headers(app, sender)

        response = client.get('/api/messages/search?q=%00', headers=headers)
        # Must not be a server error; 200 or 400 are both acceptable
        assert response.status_code in (200, 400)

    def test_sqli_second_order_payload_is_stored_literally(self, app, client, db_session):
        """
        A payload stored in a message and then retrieved via search must be
        returned as literal text and must not be interpreted as SQL.
        """
        sender = _create_user(db_session, 'sqli_u11', 'sqli_u11@example.com')
        receiver = _create_user(db_session, 'sqli_u11r', 'sqli_u11r@example.com')
        injection_payload = "' OR '1'='1"
        _create_message(
            db_session, sender, receiver,
            'Stored payload', injection_payload
        )
        headers = _auth_headers(app, sender)

        # Search for a safe substring that matches only the stored message
        response = client.get('/api/messages/search?q=Stored+payload', headers=headers)
        assert response.status_code == 200

        data = response.get_json()
        # Exactly one result — the stored message — should be returned
        assert len(data['results']) == 1
        # The content must equal the raw payload string, not be misinterpreted
        assert data['results'][0]['content'] == injection_payload
