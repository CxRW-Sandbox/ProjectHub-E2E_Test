"""
Security tests for SQL injection prevention in /api/projects endpoint.

These tests verify that the get_projects endpoint correctly uses parameterized
queries instead of string-formatted SQL, preventing SQL injection attacks
(CWE-89).
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import db, User, Project


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


def _create_project(db_session, name, description, owner_id, is_public=False):
    """Create a project directly in the test database."""
    project = Project(
        name=name,
        description=description,
        owner_id=owner_id,
        is_public=is_public,
    )
    db_session.add(project)
    db_session.commit()
    return project


def _auth_headers(app, user):
    """Return Bearer token headers for the given user."""
    with app.app_context():
        from auth import generate_token
        token = generate_token(user.id, user.username)
        return {'Authorization': f'Bearer {token}'}


# ---------------------------------------------------------------------------
# Functional tests – verify that legitimate searches work correctly
# ---------------------------------------------------------------------------

class TestGetProjectsSearchFunctionality:
    """Verify that the search feature works correctly after the parameterization fix."""

    def test_get_projects_no_search_returns_all(self, client, app, db_session):
        """Without a search parameter all projects are returned (ORM path)."""
        owner = _create_user(db_session, 'owner_a', 'owner_a@example.com')
        _create_project(db_session, 'Alpha', 'First project', owner.id)
        _create_project(db_session, 'Beta', 'Second project', owner.id)

        headers = _auth_headers(app, owner)
        response = client.get('/api/projects', headers=headers)
        assert response.status_code == 200

        data = response.get_json()
        assert 'projects' in data
        names = [p['name'] for p in data['projects']]
        assert 'Alpha' in names
        assert 'Beta' in names

    def test_get_projects_search_by_name(self, client, app, db_session):
        """Search term matching a project name returns the correct project."""
        owner = _create_user(db_session, 'owner_b', 'owner_b@example.com')
        _create_project(db_session, 'SearchMe', 'Findable project', owner.id)
        _create_project(db_session, 'Hidden', 'Not returned', owner.id)

        headers = _auth_headers(app, owner)
        response = client.get('/api/projects?search=SearchMe', headers=headers)
        assert response.status_code == 200

        data = response.get_json()
        names = [p['name'] for p in data['projects']]
        assert 'SearchMe' in names
        assert 'Hidden' not in names

    def test_get_projects_search_by_description(self, client, app, db_session):
        """Search term matching a project description returns the correct project."""
        owner = _create_user(db_session, 'owner_c', 'owner_c@example.com')
        _create_project(db_session, 'Proj1', 'unique_description_xyz', owner.id)
        _create_project(db_session, 'Proj2', 'ordinary description', owner.id)

        headers = _auth_headers(app, owner)
        response = client.get('/api/projects?search=unique_description_xyz', headers=headers)
        assert response.status_code == 200

        data = response.get_json()
        names = [p['name'] for p in data['projects']]
        assert 'Proj1' in names
        assert 'Proj2' not in names

    def test_get_projects_search_partial_match(self, client, app, db_session):
        """Partial search term matches substrings in name or description."""
        owner = _create_user(db_session, 'owner_d', 'owner_d@example.com')
        _create_project(db_session, 'MySpecialProject', 'A special one', owner.id)

        headers = _auth_headers(app, owner)
        response = client.get('/api/projects?search=Special', headers=headers)
        assert response.status_code == 200

        data = response.get_json()
        names = [p['name'] for p in data['projects']]
        assert 'MySpecialProject' in names

    def test_get_projects_search_no_match_returns_empty(self, client, app, db_session):
        """A search term that matches nothing returns an empty list."""
        owner = _create_user(db_session, 'owner_e', 'owner_e@example.com')
        _create_project(db_session, 'RegularProject', 'Regular description', owner.id)

        headers = _auth_headers(app, owner)
        response = client.get('/api/projects?search=zzznomatch', headers=headers)
        assert response.status_code == 200

        data = response.get_json()
        assert data['projects'] == []

    def test_get_projects_empty_search_returns_all(self, client, app, db_session):
        """An explicitly empty search string returns all projects (ORM path)."""
        owner = _create_user(db_session, 'owner_f', 'owner_f@example.com')
        _create_project(db_session, 'ProjectF', 'desc f', owner.id)

        headers = _auth_headers(app, owner)
        response = client.get('/api/projects?search=', headers=headers)
        assert response.status_code == 200

        data = response.get_json()
        assert len(data['projects']) >= 1

    def test_get_projects_requires_authentication(self, client):
        """Unauthenticated requests must be rejected with 401."""
        response = client.get('/api/projects?search=test')
        assert response.status_code == 401


# ---------------------------------------------------------------------------
# Security tests – SQL injection payloads must NOT alter query behaviour
# ---------------------------------------------------------------------------

class TestGetProjectsSQLInjectionPrevention:
    """
    Verify that SQL injection payloads in the 'search' parameter are treated
    as literal strings and do not affect the query's structure or results.

    With the parameterized fix each payload is bound as a LIKE pattern value,
    so none of these should raise a database error or return unexpected rows.
    """

    def test_sqli_or_true_tautology(self, client, app, db_session):
        """
        Classic OR-1=1 tautology must NOT return all rows when no real match exists.

        Without parameterization  '%' OR '1'='1  would match every row.
        With parameterization the entire string is the LIKE pattern, so
        it can only match a name/description that literally contains that text.
        """
        owner = _create_user(db_session, 'sqli_user_1', 'sqli1@example.com')
        _create_project(db_session, 'TargetProject', 'desc', owner.id)

        headers = _auth_headers(app, owner)
        # Payload: ' OR '1'='1
        payload = "' OR '1'='1"
        response = client.get(f'/api/projects?search={payload}', headers=headers)
        assert response.status_code == 200

        data = response.get_json()
        # 'TargetProject' should NOT be returned – the payload is not its name or description
        names = [p['name'] for p in data['projects']]
        assert 'TargetProject' not in names

    def test_sqli_single_quote_does_not_error(self, client, app, db_session):
        """A bare single-quote in the search parameter must not raise a DB error."""
        owner = _create_user(db_session, 'sqli_user_2', 'sqli2@example.com')
        headers = _auth_headers(app, owner)
        response = client.get("/api/projects?search='", headers=headers)
        assert response.status_code == 200

    def test_sqli_double_quote_does_not_error(self, client, app, db_session):
        """A double-quote in the search parameter must not raise a DB error."""
        owner = _create_user(db_session, 'sqli_user_3', 'sqli3@example.com')
        headers = _auth_headers(app, owner)
        response = client.get('/api/projects?search="', headers=headers)
        assert response.status_code == 200

    def test_sqli_semicolon_does_not_execute_second_statement(self, client, app, db_session):
        """
        A semicolon followed by DROP/DELETE must not cause any error or
        affect the database.
        """
        owner = _create_user(db_session, 'sqli_user_4', 'sqli4@example.com')
        _create_project(db_session, 'SurvivingProject', 'must survive', owner.id)

        headers = _auth_headers(app, owner)
        payload = "x'; DROP TABLE projects; --"
        response = client.get(f'/api/projects?search={payload}', headers=headers)
        # Must not crash
        assert response.status_code == 200

        # The projects table must still exist and contain 'SurvivingProject'
        get_all = client.get('/api/projects', headers=headers)
        assert get_all.status_code == 200
        names = [p['name'] for p in get_all.get_json()['projects']]
        assert 'SurvivingProject' in names

    def test_sqli_comment_sequence_does_not_alter_results(self, client, app, db_session):
        """SQL comment sequences (-- and #) in the search must be treated literally."""
        owner = _create_user(db_session, 'sqli_user_5', 'sqli5@example.com')
        _create_project(db_session, 'CommentTestProject', 'test desc', owner.id)

        headers = _auth_headers(app, owner)
        for payload in ["--", "#", "' --", "admin'--"]:
            response = client.get(f'/api/projects?search={payload}', headers=headers)
            assert response.status_code == 200, f"Payload '{payload}' caused an error"
            data = response.get_json()
            names = [p['name'] for p in data['projects']]
            # 'CommentTestProject' must not appear – none of these payloads are
            # substrings of the project name or description
            assert 'CommentTestProject' not in names, (
                f"Payload '{payload}' unexpectedly returned project 'CommentTestProject'"
            )

    def test_sqli_union_select_does_not_return_extra_rows(self, client, app, db_session):
        """
        A UNION SELECT payload must not inject additional rows into the result.
        The parameterized LIKE treats the whole string as a literal value.
        """
        owner = _create_user(db_session, 'sqli_user_6', 'sqli6@example.com')
        headers = _auth_headers(app, owner)

        payload = "x' UNION SELECT 1,2,3,4,5,6,7 --"
        response = client.get(f'/api/projects?search={payload}', headers=headers)
        assert response.status_code == 200

        data = response.get_json()
        # No rows should match the literal LIKE pattern containing UNION SELECT
        assert data['projects'] == []

    def test_sqli_wildcard_percent_treated_as_safe(self, client, app, db_session):
        """
        A bare '%' is a valid LIKE wildcard; this test verifies no SQL error
        is raised when it is provided as the search term.
        """
        owner = _create_user(db_session, 'sqli_user_7', 'sqli7@example.com')
        headers = _auth_headers(app, owner)

        response = client.get('/api/projects?search=%25', headers=headers)  # URL-encoded '%'
        assert response.status_code == 200

    def test_sqli_null_byte_does_not_error(self, client, app, db_session):
        """
        A null byte (%00) in the search parameter must not cause a server error.
        Expressed as the URL-encoded form so no raw control byte is embedded in
        this source file.
        """
        owner = _create_user(db_session, 'sqli_user_8', 'sqli8@example.com')
        headers = _auth_headers(app, owner)

        response = client.get('/api/projects?search=%00', headers=headers)
        # Must not crash with 500
        assert response.status_code in (200, 400)

    def test_sqli_backslash_does_not_error(self, client, app, db_session):
        """Backslash sequences in the search must not cause a server error."""
        owner = _create_user(db_session, 'sqli_user_9', 'sqli9@example.com')
        headers = _auth_headers(app, owner)

        response = client.get("/api/projects?search=\\", headers=headers)
        assert response.status_code == 200

    def test_sqli_special_chars_combo_does_not_error(self, client, app, db_session):
        """A combination of special characters must not cause a server error."""
        owner = _create_user(db_session, 'sqli_user_10', 'sqli10@example.com')
        headers = _auth_headers(app, owner)

        payload = "'; SELECT * FROM projects WHERE ''='"
        response = client.get(f'/api/projects?search={payload}', headers=headers)
        assert response.status_code == 200

    def test_sqli_encoded_quote_does_not_error(self, client, app, db_session):
        """URL-encoded single quote (%27) must not cause a server error."""
        owner = _create_user(db_session, 'sqli_user_11', 'sqli11@example.com')
        headers = _auth_headers(app, owner)

        response = client.get('/api/projects?search=%27', headers=headers)
        assert response.status_code == 200

    def test_sqli_stacked_query_does_not_alter_data(self, client, app, db_session):
        """
        A stacked query payload must not delete or alter existing data.
        The parameterized query driver does not allow multi-statement execution
        via a bound parameter.
        """
        owner = _create_user(db_session, 'sqli_user_12', 'sqli12@example.com')
        _create_project(db_session, 'ImmutableProject', 'should remain', owner.id)

        headers = _auth_headers(app, owner)
        payload = "x'; DELETE FROM projects; --"
        response = client.get(f'/api/projects?search={payload}', headers=headers)
        # Must not crash
        assert response.status_code == 200

        # The projects table must still contain 'ImmutableProject'
        get_all = client.get('/api/projects', headers=headers)
        assert get_all.status_code == 200
        names = [p['name'] for p in get_all.get_json()['projects']]
        assert 'ImmutableProject' in names

    def test_sqli_or_1_equals_1_integer_variant(self, client, app, db_session):
        """
        Integer-based tautology (1 OR 1=1) must not return all rows.
        With parameterization the payload is the literal LIKE value,
        not injected SQL.
        """
        owner = _create_user(db_session, 'sqli_user_13', 'sqli13@example.com')
        _create_project(db_session, 'IntPayloadProject', 'desc', owner.id)

        headers = _auth_headers(app, owner)
        payload = "1 OR 1=1"
        response = client.get(f'/api/projects?search={payload}', headers=headers)
        assert response.status_code == 200

        data = response.get_json()
        names = [p['name'] for p in data['projects']]
        # The project name does not contain the payload literally
        assert 'IntPayloadProject' not in names
