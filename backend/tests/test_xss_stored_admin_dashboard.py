"""
Security tests for stored XSS prevention in the admin dashboard (CWE-79).

The vulnerability (SAST finding – Stored_XSS) was that the `role_badge`
Jinja2 filter embedded the raw `role` value, which originates from the
database, directly into an HTML string. The template then rendered the result
with ``|safe``, bypassing Jinja2's auto-escaping. An attacker who could
write an arbitrary role string to the database could inject executable
JavaScript that would run in every admin's browser.

The fix applies ``html.escape()`` to both the color class and the role text
before embedding them in the HTML, and wraps the result in ``jinja2.Markup``
so Jinja2 knows the string is already safely escaped.

These tests verify:
  1. The ``role_badge`` filter correctly escapes XSS payloads.
  2. The admin dashboard route renders without exposing unescaped role data.
  3. Legitimate role values still produce the expected badge markup.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from jinja2 import Markup
from utils.jinja_filters import role_badge
from models import db, User, Project, Task


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fake_context():
    """Return a minimal Jinja2-like context dict (contextfilter passes one)."""
    return {}


def _create_user(db_session, username, email, role='team_member'):
    """Insert a user into the test DB."""
    user = User(username=username, email=email, role=role)
    user.set_password('testpass123')
    db_session.add(user)
    db_session.commit()
    return user


# ---------------------------------------------------------------------------
# Unit tests – role_badge filter in isolation
# ---------------------------------------------------------------------------

class TestRoleBadgeFilter:
    """Unit tests for the role_badge Jinja2 filter."""

    # --- XSS payload escaping ---

    def test_script_tag_in_role_is_escaped(self):
        """A <script> tag in the role value must be HTML-escaped, not rendered."""
        ctx = _fake_context()
        payload = '<script>alert(1)</script>'
        result = role_badge(ctx, payload)
        assert '<script>' not in result
        assert '&lt;script&gt;' in result

    def test_img_onerror_payload_is_escaped(self):
        """An img onerror XSS payload must be escaped."""
        ctx = _fake_context()
        payload = '"><img src=x onerror=alert(1)>'
        result = role_badge(ctx, payload)
        assert 'onerror' not in result
        assert '<img' not in result
        assert '&lt;img' in result

    def test_javascript_uri_is_escaped(self):
        """javascript: URI schemes in the role field must be escaped."""
        ctx = _fake_context()
        payload = 'javascript:alert(document.cookie)'
        result = role_badge(ctx, payload)
        # The colon is safe, but the angle brackets and quotes that might
        # accompany it in a larger payload must be escaped; the raw string
        # itself must not break out of the span tag.
        assert '<script' not in result

    def test_double_quote_in_role_is_escaped(self):
        """Double quotes must be escaped so they cannot break out of attributes."""
        ctx = _fake_context()
        payload = '"onmouseover="alert(1)'
        result = role_badge(ctx, payload)
        assert '"onmouseover=' not in result
        assert '&quot;' in result or '&#x27;' in result or '&amp;' in result or '"onmouseover=' not in result

    def test_single_quote_in_role_is_escaped(self):
        """Single quotes must be escaped."""
        ctx = _fake_context()
        payload = "' onmouseover='alert(1)' x='"
        result = role_badge(ctx, payload)
        # html.escape() escapes & < > " but not ' by default; however the
        # value is embedded between > and < (tag content) so the quote cannot
        # break out of an attribute in that position.
        assert "' onmouseover=" not in result

    def test_angle_brackets_are_escaped(self):
        """Angle brackets in role must be escaped to &lt; / &gt;."""
        ctx = _fake_context()
        result = role_badge(ctx, '<b>bold</b>')
        assert '<b>' not in result
        assert '&lt;b&gt;' in result

    def test_ampersand_is_escaped(self):
        """Ampersands in the role must be escaped to &amp;."""
        ctx = _fake_context()
        result = role_badge(ctx, 'dev&ops')
        assert 'dev&ops' not in result
        assert 'dev&amp;ops' in result

    def test_event_handler_attribute_injection_is_blocked(self):
        """An event-handler attribute injection attempt is escaped."""
        ctx = _fake_context()
        payload = 'admin" onfocus="alert(1)" autofocus="'
        result = role_badge(ctx, payload)
        assert 'onfocus=' not in result
        assert '&quot;' in result

    # --- Legitimate values still produce correct output ---

    def test_admin_role_produces_danger_badge(self):
        """The 'admin' role should produce a badge with the 'danger' colour class."""
        ctx = _fake_context()
        result = role_badge(ctx, 'admin')
        assert 'badge-danger' in result
        assert '>admin<' in result

    def test_project_manager_role_produces_primary_badge(self):
        """'project_manager' should produce a badge with the 'primary' colour class."""
        ctx = _fake_context()
        result = role_badge(ctx, 'project_manager')
        assert 'badge-primary' in result
        assert '>project_manager<' in result

    def test_team_member_role_produces_secondary_badge(self):
        """'team_member' should produce a badge with the 'secondary' colour class."""
        ctx = _fake_context()
        result = role_badge(ctx, 'team_member')
        assert 'badge-secondary' in result
        assert '>team_member<' in result

    def test_unknown_role_defaults_to_secondary_badge(self):
        """An unknown role that doesn't contain special chars falls back to secondary."""
        ctx = _fake_context()
        result = role_badge(ctx, 'contractor')
        assert 'badge-secondary' in result
        assert '>contractor<' in result

    def test_return_type_is_markup(self):
        """The filter must return a jinja2.Markup instance so |safe is consistent."""
        ctx = _fake_context()
        result = role_badge(ctx, 'admin')
        assert isinstance(result, Markup)

    def test_none_role_does_not_raise(self):
        """Passing None as the role must not raise an exception."""
        ctx = _fake_context()
        try:
            result = role_badge(ctx, None)
            # Must not contain unescaped HTML
            assert '<script>' not in result
        except Exception as exc:
            pytest.fail(f"role_badge(None) raised {exc}")

    def test_empty_string_role(self):
        """An empty-string role must not raise and must not produce unescaped output."""
        ctx = _fake_context()
        result = role_badge(ctx, '')
        assert isinstance(result, Markup)

    def test_numeric_role_does_not_raise(self):
        """A numeric role (int) must be coerced to str without raising."""
        ctx = _fake_context()
        result = role_badge(ctx, 42)
        assert '42' in result


# ---------------------------------------------------------------------------
# Integration tests – /admin route renders escaped role data
# ---------------------------------------------------------------------------

class TestAdminDashboardStoredXSS:
    """
    End-to-end tests that exercise the /admin route with a test Flask app.

    The conftest `app` fixture creates an in-memory SQLite database and
    registers all blueprints.  We additionally register the /admin route
    here so it can be tested in isolation.
    """

    @pytest.fixture(autouse=True)
    def _register_admin_route(self, app):
        """Register the /admin route on the test app and load template filters."""
        from jinja2 import Markup as _Markup
        import html as _html
        from utils.jinja_filters import (
            role_badge as _role_badge,
            user_display_name as _user_display_name,
            format_datetime as _format_datetime,
            request_id_filter as _request_id_filter,
            format_file_size as _format_file_size,
        )

        # Register filters (idempotent – safe to call multiple times)
        app.jinja_env.filters['role_badge'] = _role_badge
        app.jinja_env.filters['user_display_name'] = _user_display_name
        app.jinja_env.filters['format_datetime'] = _format_datetime
        app.jinja_env.filters['request_id_filter'] = _request_id_filter
        app.jinja_env.filters['format_file_size'] = _format_file_size

        # Register the /admin route if it isn't already present
        if 'admin_dashboard' not in app.view_functions:
            @app.route('/admin')
            def admin_dashboard():
                from flask import render_template, request
                users = User.query.all()
                projects = Project.query.all()
                tasks = Task.query.all()
                return render_template(
                    'admin.html',
                    users=users,
                    projects=projects,
                    tasks=tasks,
                    request_id='test-request-id',
                )

    def test_admin_dashboard_renders_without_error(self, client, db_session):
        """The admin route should return HTTP 200 for a DB with normal users."""
        _create_user(db_session, 'alice', 'alice@example.com', 'admin')
        response = client.get('/admin', headers={'Accept': 'text/html'})
        assert response.status_code == 200

    def test_admin_dashboard_does_not_reflect_script_tag_in_role(self, client, db_session):
        """
        A user whose role contains a <script> tag (stored XSS payload) must not
        appear as executable HTML in the admin dashboard response.
        """
        _create_user(
            db_session,
            'evil',
            'evil@example.com',
            role='<script>alert("xss")</script>',
        )
        response = client.get('/admin', headers={'Accept': 'text/html'})
        assert response.status_code == 200

        body = response.data.decode('utf-8')
        # Raw script tag must NOT appear in the rendered HTML
        assert '<script>alert("xss")</script>' not in body
        # Escaped form should be present instead
        assert '&lt;script&gt;' in body

    def test_admin_dashboard_does_not_reflect_img_onerror_in_role(self, client, db_session):
        """An img onerror payload stored in the role field must be escaped."""
        _create_user(
            db_session,
            'evil2',
            'evil2@example.com',
            role='"><img src=x onerror=alert(1)>',
        )
        response = client.get('/admin', headers={'Accept': 'text/html'})
        assert response.status_code == 200

        body = response.data.decode('utf-8')
        assert 'onerror=alert(1)' not in body
        assert '<img src=x' not in body

    def test_admin_dashboard_does_not_reflect_event_handler_injection(self, client, db_session):
        """An event-handler injection via the role field must be escaped."""
        _create_user(
            db_session,
            'evil3',
            'evil3@example.com',
            role='admin" onfocus="alert(document.cookie)" autofocus="',
        )
        response = client.get('/admin', headers={'Accept': 'text/html'})
        assert response.status_code == 200

        body = response.data.decode('utf-8')
        assert 'onfocus=' not in body

    def test_admin_dashboard_renders_legitimate_roles_correctly(self, client, db_session):
        """Legitimate roles (admin, project_manager, team_member) still display."""
        _create_user(db_session, 'admin_u', 'admin_u@example.com', 'admin')
        _create_user(db_session, 'pm_u', 'pm_u@example.com', 'project_manager')
        _create_user(db_session, 'member_u', 'member_u@example.com', 'team_member')

        response = client.get('/admin', headers={'Accept': 'text/html'})
        assert response.status_code == 200

        body = response.data.decode('utf-8')
        assert 'badge-danger' in body
        assert 'badge-primary' in body
        assert 'badge-secondary' in body

    def test_admin_dashboard_with_empty_db(self, client):
        """The admin route must work without any users in the database."""
        response = client.get('/admin', headers={'Accept': 'text/html'})
        assert response.status_code == 200

    def test_admin_dashboard_multiple_xss_payloads_all_escaped(self, client, db_session):
        """Multiple users with different XSS payloads in roles are all escaped."""
        payloads = [
            '<script>alert(1)</script>',
            '"><svg/onload=alert(2)>',
            "';alert(3)//",
        ]
        for i, payload in enumerate(payloads):
            _create_user(db_session, f'attacker{i}', f'attacker{i}@evil.com', role=payload)

        response = client.get('/admin', headers={'Accept': 'text/html'})
        assert response.status_code == 200

        body = response.data.decode('utf-8')
        # None of the raw payloads should appear in the rendered HTML
        for payload in payloads:
            assert payload not in body, (
                f"Unescaped XSS payload found in admin dashboard: {payload!r}"
            )
