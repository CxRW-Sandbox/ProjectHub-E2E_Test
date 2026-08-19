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


# ---------------------------------------------------------------------------
# Helpers for projects tests
# ---------------------------------------------------------------------------

def _create_project(db_session, name, description, owner_id):
    """Create a project directly in the test database."""
    from models import Project
    project = Project(
        name=name,
        description=description,
        owner_id=owner_id,
        is_public=False,
    )
    db_session.add(project)
    db_session.commit()
    return project


def _create_owner(db_session, username='owner', email='owner@example.com'):
    """Create a user to own test projects."""
    from models import User
    # Avoid duplicates when called multiple times
    existing = db_session.query(User).filter_by(username=username).first()
    if existing:
        return existing
    user = User(username=username, email=email, role='team_member')
    user.set_password('ownerpass123')
    db_session.add(user)
    db_session.commit()
    return user


# ---------------------------------------------------------------------------
# Functional tests – /api/v1/projects search works correctly
# ---------------------------------------------------------------------------

class TestGetProjectsSearchFunctionality:
    """Verify that the search feature on /api/v1/projects works correctly
    after the parameterized-query fix (CWE-89)."""

    def test_get_projects_no_search_returns_all(self, client, db_session):
        """Without a search parameter all projects are returned."""
        owner = _create_owner(db_session)
        _create_project(db_session, 'Alpha', 'First project', owner.id)
        _create_project(db_session, 'Beta', 'Second project', owner.id)

        response = client.get('/api/v1/projects')
        assert response.status_code == 200

        data = response.get_json()
        assert 'projects' in data
        assert len(data['projects']) >= 2

    def test_get_projects_search_by_name(self, client, db_session):
        """Search term matching a project name returns the correct project."""
        owner = _create_owner(db_session)
        _create_project(db_session, 'UniqueAlpha', 'Some description', owner.id)
        _create_project(db_session, 'TotallyOther', 'Other description', owner.id)

        response = client.get('/api/v1/projects?search=UniqueAlpha')
        assert response.status_code == 200

        data = response.get_json()
        names = [p['name'] for p in data['projects']]
        assert 'UniqueAlpha' in names
        assert 'TotallyOther' not in names

    def test_get_projects_search_by_description(self, client, db_session):
        """Search term matching a description returns the correct project."""
        owner = _create_owner(db_session)
        _create_project(db_session, 'ProjA', 'Contains needle keyword', owner.id)
        _create_project(db_session, 'ProjB', 'Nothing special here', owner.id)

        response = client.get('/api/v1/projects?search=needle')
        assert response.status_code == 200

        data = response.get_json()
        names = [p['name'] for p in data['projects']]
        assert 'ProjA' in names
        assert 'ProjB' not in names

    def test_get_projects_search_partial_match(self, client, db_session):
        """Partial search term matches substrings in name or description."""
        owner = _create_owner(db_session)
        _create_project(db_session, 'PartialMatchProject', 'desc', owner.id)

        response = client.get('/api/v1/projects?search=PartialMatch')
        assert response.status_code == 200

        data = response.get_json()
        names = [p['name'] for p in data['projects']]
        assert 'PartialMatchProject' in names

    def test_get_projects_search_no_match_returns_empty(self, client, db_session):
        """A search term that matches nothing returns an empty list."""
        owner = _create_owner(db_session)
        _create_project(db_session, 'SomeProject', 'some description', owner.id)

        response = client.get('/api/v1/projects?search=zzznomatch')
        assert response.status_code == 200

        data = response.get_json()
        assert data['projects'] == []

    def test_get_projects_empty_search_returns_all(self, client, db_session):
        """An explicitly empty search string returns all projects (ORM path)."""
        owner = _create_owner(db_session)
        _create_project(db_session, 'EmptySearchProject', 'desc', owner.id)

        response = client.get('/api/v1/projects?search=')
        assert response.status_code == 200

        data = response.get_json()
        assert len(data['projects']) >= 1

    def test_get_projects_response_contains_projects_key(self, client, db_session):
        """Response always contains the 'projects' key."""
        response = client.get('/api/v1/projects')
        assert response.status_code == 200
        assert 'projects' in response.get_json()

    def test_get_projects_response_project_has_expected_fields(self, client, db_session):
        """Each project in the response has the expected fields."""
        owner = _create_owner(db_session)
        _create_project(db_session, 'FieldCheckProject', 'field description', owner.id)

        response = client.get('/api/v1/projects?search=FieldCheckProject')
        assert response.status_code == 200

        data = response.get_json()
        assert len(data['projects']) >= 1
        project = data['projects'][0]
        for field in ('id', 'name', 'description', 'owner_id'):
            assert field in project, f"Expected field '{field}' missing from project dict"


# ---------------------------------------------------------------------------
# Security tests – SQL injection payloads must NOT alter query behaviour
# ---------------------------------------------------------------------------

class TestGetProjectsSQLInjectionPrevention:
    """
    Verify that SQL injection payloads in the 'search' parameter of
    /api/v1/projects are treated as literal strings and do not affect
    the query's structure or results (CWE-89 remediation).

    With the parameterized fix each payload is bound as a LIKE pattern value,
    so none of these should raise a database error or return unexpected rows.
    """

    def test_sqli_or_true_tautology_does_not_return_all_rows(self, client, db_session):
        """
        Classic OR-1=1 tautology must NOT return all rows when no real match exists.

        Without parameterization  ' OR '1'='1  would match every row.
        With parameterization the entire string is the LIKE pattern, so
        it can only match a project whose name/description literally contains that text.
        """
        owner = _create_owner(db_session)
        _create_project(db_session, 'SecretProject', 'confidential', owner.id)

        payload = "' OR '1'='1"
        response = client.get(f'/api/v1/projects?search={payload}')
        assert response.status_code == 200

        data = response.get_json()
        names = [p['name'] for p in data['projects']]
        assert 'SecretProject' not in names

    def test_sqli_single_quote_does_not_error(self, client, db_session):
        """A bare single-quote in the search parameter must not raise a DB error."""
        response = client.get("/api/v1/projects?search='")
        assert response.status_code == 200

    def test_sqli_double_quote_does_not_error(self, client, db_session):
        """A double-quote in the search parameter must not raise a DB error."""
        response = client.get('/api/v1/projects?search="')
        assert response.status_code == 200

    def test_sqli_semicolon_drop_table_does_not_execute(self, client, db_session):
        """
        A semicolon followed by DROP TABLE must not cause any error or
        affect the database.
        """
        owner = _create_owner(db_session)
        _create_project(db_session, 'DropProof', 'should survive', owner.id)

        payload = "x'; DROP TABLE projects; --"
        response = client.get(f'/api/v1/projects?search={payload}')
        assert response.status_code == 200

        # The projects table must still exist and contain our project
        get_all = client.get('/api/v1/projects')
        assert get_all.status_code == 200
        names = [p['name'] for p in get_all.get_json()['projects']]
        assert 'DropProof' in names

    def test_sqli_comment_sequence_does_not_alter_results(self, client, db_session):
        """SQL comment sequences (-- and #) in the search must be treated literally."""
        owner = _create_owner(db_session)
        _create_project(db_session, 'CommentTestProject', 'desc', owner.id)

        for payload in ["--", "#", "' --", "admin'--"]:
            response = client.get(f'/api/v1/projects?search={payload}')
            assert response.status_code == 200, f"Payload '{payload}' caused an error"
            data = response.get_json()
            names = [p['name'] for p in data['projects']]
            assert 'CommentTestProject' not in names, (
                f"Payload '{payload}' unexpectedly returned 'CommentTestProject'"
            )

    def test_sqli_union_select_does_not_return_extra_rows(self, client, db_session):
        """
        A UNION SELECT payload must not inject additional rows into the result.
        The parameterized LIKE treats the whole string as a literal value.
        """
        owner = _create_owner(db_session)
        _create_project(db_session, 'UnionProof', 'desc', owner.id)

        payload = "x' UNION SELECT 1,2,3,4,5,6,7 --"
        response = client.get(f'/api/v1/projects?search={payload}')
        assert response.status_code == 200

        data = response.get_json()
        # No rows should match the literal LIKE pattern containing UNION SELECT
        assert data['projects'] == []

    def test_sqli_or_always_true_numeric(self, client, db_session):
        """
        Numeric tautology payload must not return rows that don't match literally.
        """
        owner = _create_owner(db_session)
        _create_project(db_session, 'NumericTautologyProject', 'desc', owner.id)

        payload = "1' OR 1=1 --"
        response = client.get(f'/api/v1/projects?search={payload}')
        assert response.status_code == 200

        data = response.get_json()
        names = [p['name'] for p in data['projects']]
        assert 'NumericTautologyProject' not in names

    def test_sqli_encoded_quote_does_not_error(self, client, db_session):
        """URL-encoded single quote (%27) must not cause a server error."""
        response = client.get('/api/v1/projects?search=%27')
        assert response.status_code == 200

    def test_sqli_backslash_does_not_error(self, client, db_session):
        """Backslash sequences in the search must not cause a server error."""
        response = client.get("/api/v1/projects?search=\\")
        assert response.status_code == 200

    def test_sqli_special_chars_combo_does_not_error(self, client, db_session):
        """A combination of special characters must not cause a server error."""
        payload = "'; SELECT * FROM projects WHERE ''='"
        response = client.get(f'/api/v1/projects?search={payload}')
        assert response.status_code == 200

    def test_sqli_null_byte_does_not_error(self, client, db_session):
        """
        A null byte (%00) in the search parameter must not cause a server error.
        Expressed as the URL-encoded form so no raw control byte is embedded in
        this source file.
        """
        response = client.get('/api/v1/projects?search=%00')
        # Must not crash with 500
        assert response.status_code in (200, 400)

    def test_sqli_stacked_queries_do_not_insert_row(self, client, db_session):
        """
        A stacked INSERT query must not create a new project row.
        """
        owner = _create_owner(db_session)

        # Count rows before the injection attempt
        before = client.get('/api/v1/projects').get_json()['projects']
        before_count = len(before)

        payload = "x'; INSERT INTO projects (name, description, owner_id) VALUES ('injected', 'injected', 1); --"
        response = client.get(f'/api/v1/projects?search={payload}')
        assert response.status_code == 200

        # Count rows after; the injected row must not have been inserted
        after = client.get('/api/v1/projects').get_json()['projects']
        names = [p['name'] for p in after]
        assert 'injected' not in names


# ---------------------------------------------------------------------------
# Helpers for global_search tests
# ---------------------------------------------------------------------------

def _create_task(db_session, title, description, project_id, created_by):
    """Create a task directly in the test database."""
    from models import Task
    task = Task(
        title=title,
        description=description,
        project_id=project_id,
        created_by=created_by,
        status='pending',
        priority='medium',
    )
    db_session.add(task)
    db_session.commit()
    return task


# ---------------------------------------------------------------------------
# Functional tests – /api/v1/search endpoint works correctly
# ---------------------------------------------------------------------------

class TestGlobalSearchFunctionality:
    """
    Verify that the /api/v1/search endpoint returns correct results after
    the parameterized-query fix (CWE-89).
    """

    def test_search_requires_query_param(self, client, db_session):
        """Omitting the 'q' parameter returns a 400 error."""
        response = client.get('/api/v1/search')
        assert response.status_code == 400
        data = response.get_json()
        assert 'error' in data

    def test_search_empty_query_returns_400(self, client, db_session):
        """An explicitly empty 'q' parameter returns a 400 error."""
        response = client.get('/api/v1/search?q=')
        assert response.status_code == 400

    def test_search_response_has_expected_keys(self, client, db_session):
        """A valid search response always contains query, users, projects, tasks."""
        response = client.get('/api/v1/search?q=anything')
        assert response.status_code == 200
        data = response.get_json()
        for key in ('query', 'users', 'projects', 'tasks'):
            assert key in data, f"Expected key '{key}' missing from response"

    def test_search_returns_matching_user_by_username(self, client, db_session):
        """A search term matching a username returns that user in 'users'."""
        owner = _create_owner(db_session, username='searchable_user', email='su@example.com')

        response = client.get('/api/v1/search?q=searchable_user')
        assert response.status_code == 200

        data = response.get_json()
        usernames = [u.get('username') for u in data['users']]
        assert 'searchable_user' in usernames

    def test_search_returns_matching_project_by_name(self, client, db_session):
        """A search term matching a project name returns that project in 'projects'."""
        owner = _create_owner(db_session)
        _create_project(db_session, 'SearchableProject', 'some desc', owner.id)

        response = client.get('/api/v1/search?q=SearchableProject')
        assert response.status_code == 200

        data = response.get_json()
        names = [p.get('name') for p in data['projects']]
        assert 'SearchableProject' in names

    def test_search_returns_matching_task_by_title(self, client, db_session):
        """A search term matching a task title returns that task in 'tasks'."""
        owner = _create_owner(db_session)
        project = _create_project(db_session, 'TaskProject', 'desc', owner.id)
        _create_task(db_session, 'SearchableTask', 'some task desc', project.id, owner.id)

        response = client.get('/api/v1/search?q=SearchableTask')
        assert response.status_code == 200

        data = response.get_json()
        titles = [t.get('title') for t in data['tasks']]
        assert 'SearchableTask' in titles

    def test_search_no_match_returns_empty_lists(self, client, db_session):
        """A query that matches nothing returns empty lists for all categories."""
        response = client.get('/api/v1/search?q=zzznomatch_xyz_unique')
        assert response.status_code == 200

        data = response.get_json()
        assert data['users'] == []
        assert data['projects'] == []
        assert data['tasks'] == []

    def test_search_query_echoed_in_response(self, client, db_session):
        """The 'query' field in the response matches the submitted search term."""
        term = 'mytestquery'
        response = client.get(f'/api/v1/search?q={term}')
        assert response.status_code == 200

        data = response.get_json()
        assert data['query'] == term


# ---------------------------------------------------------------------------
# Security tests – SQL injection payloads in /api/v1/search must be treated
# as literal strings and must NOT alter query structure or results (CWE-89)
# ---------------------------------------------------------------------------

class TestGlobalSearchSQLInjectionPrevention:
    """
    Verify that the global_search endpoint's parameterized queries prevent
    SQL injection.  Each payload is bound as a LIKE pattern value so it
    cannot escape the query structure.
    """

    def test_sqli_or_tautology_does_not_return_all_users(self, client, db_session):
        """
        Classic OR-1=1 tautology must NOT return rows that don't match literally.

        Without parameterization the payload would make the WHERE clause always
        true and expose every user.  With parameterized bindings the entire string
        is the LIKE operand and only matches a username/email containing that text.
        """
        _create_user(db_session, 'sqli_user_gs', 'sqli_gs@example.com')

        payload = "' OR '1'='1"
        response = client.get(f'/api/v1/search?q={payload}')
        assert response.status_code == 200

        data = response.get_json()
        usernames = [u.get('username') for u in data['users']]
        assert 'sqli_user_gs' not in usernames

    def test_sqli_or_tautology_does_not_return_all_projects(self, client, db_session):
        """
        Classic OR-1=1 tautology must NOT return all projects when no real match exists.
        """
        owner = _create_owner(db_session)
        _create_project(db_session, 'SecretSearchProject', 'confidential', owner.id)

        payload = "' OR '1'='1"
        response = client.get(f'/api/v1/search?q={payload}')
        assert response.status_code == 200

        data = response.get_json()
        names = [p.get('name') for p in data['projects']]
        assert 'SecretSearchProject' not in names

    def test_sqli_or_tautology_does_not_return_all_tasks(self, client, db_session):
        """
        Classic OR-1=1 tautology must NOT return all tasks when no real match exists.
        """
        owner = _create_owner(db_session)
        project = _create_project(db_session, 'TautologyTaskProject', 'desc', owner.id)
        _create_task(db_session, 'SecretSearchTask', 'confidential task', project.id, owner.id)

        payload = "' OR '1'='1"
        response = client.get(f'/api/v1/search?q={payload}')
        assert response.status_code == 200

        data = response.get_json()
        titles = [t.get('title') for t in data['tasks']]
        assert 'SecretSearchTask' not in titles

    def test_sqli_single_quote_does_not_error(self, client, db_session):
        """A bare single-quote must not raise a DB error."""
        response = client.get("/api/v1/search?q='")
        assert response.status_code == 200

    def test_sqli_double_quote_does_not_error(self, client, db_session):
        """A double-quote must not raise a DB error."""
        response = client.get('/api/v1/search?q="')
        assert response.status_code == 200

    def test_sqli_comment_sequences_do_not_alter_results(self, client, db_session):
        """SQL comment sequences (-- and #) must be treated as literal strings."""
        _create_user(db_session, 'comment_user_gs', 'comment_gs@example.com')

        for payload in ["--", "#", "' --", "admin'--"]:
            response = client.get(f'/api/v1/search?q={payload}')
            assert response.status_code == 200, f"Payload '{payload}' caused an error"
            data = response.get_json()
            usernames = [u.get('username') for u in data['users']]
            assert 'comment_user_gs' not in usernames, (
                f"Payload '{payload}' unexpectedly returned user 'comment_user_gs'"
            )

    def test_sqli_semicolon_drop_table_does_not_execute(self, client, db_session):
        """
        A stacked DROP TABLE payload must not crash the server or destroy tables.
        """
        owner = _create_owner(db_session)
        _create_project(db_session, 'SurvivesSearchDrop', 'should survive', owner.id)

        payload = "x'; DROP TABLE projects; --"
        response = client.get(f'/api/v1/search?q={payload}')
        assert response.status_code == 200

        # The projects table must still be queryable
        get_all = client.get('/api/v1/projects')
        assert get_all.status_code == 200
        names = [p['name'] for p in get_all.get_json()['projects']]
        assert 'SurvivesSearchDrop' in names

    def test_sqli_union_select_users_table(self, client, db_session):
        """
        A UNION SELECT payload targeting the users table must not inject extra rows.
        The parameterized LIKE treats the whole string as a literal value.
        """
        payload = "x' UNION SELECT id,username,email,password,role,created_at FROM users --"
        response = client.get(f'/api/v1/search?q={payload}')
        assert response.status_code == 200

        data = response.get_json()
        # All result lists should be empty — the literal LIKE pattern won't match anything
        assert data['users'] == []
        assert data['projects'] == []
        assert data['tasks'] == []

    def test_sqli_union_select_does_not_return_extra_project_rows(self, client, db_session):
        """
        A UNION SELECT payload targeting projects must not inject rows into results.
        """
        payload = "x' UNION SELECT 1,2,3,4,5,6,7 --"
        response = client.get(f'/api/v1/search?q={payload}')
        assert response.status_code == 200

        data = response.get_json()
        assert data['projects'] == []

    def test_sqli_numeric_tautology_does_not_return_rows(self, client, db_session):
        """
        A numeric tautology (1=1) must not cause all rows to be returned.
        """
        owner = _create_owner(db_session)
        _create_project(db_session, 'NumericTautologySearchProject', 'desc', owner.id)

        payload = "1' OR 1=1 --"
        response = client.get(f'/api/v1/search?q={payload}')
        assert response.status_code == 200

        data = response.get_json()
        names = [p.get('name') for p in data['projects']]
        assert 'NumericTautologySearchProject' not in names

    def test_sqli_encoded_quote_does_not_error(self, client, db_session):
        """URL-encoded single quote (%27) must not cause a server error."""
        response = client.get('/api/v1/search?q=%27')
        assert response.status_code == 200

    def test_sqli_null_byte_does_not_error(self, client, db_session):
        """
        A null byte (%00) in the query parameter must not cause a server error.
        Expressed as the URL-encoded form so no raw control byte is embedded in
        this source file.
        """
        response = client.get('/api/v1/search?q=%00')
        # Must not crash with 500; 400 is acceptable if the app rejects it
        assert response.status_code in (200, 400)

    def test_sqli_backslash_does_not_error(self, client, db_session):
        """Backslash sequences in the query must not cause a server error."""
        response = client.get("/api/v1/search?q=\\")
        assert response.status_code == 200

    def test_sqli_special_chars_combo_does_not_error(self, client, db_session):
        """A combination of special SQL characters must not cause a server error."""
        payload = "'; SELECT * FROM users WHERE ''='"
        response = client.get(f'/api/v1/search?q={payload}')
        assert response.status_code == 200

    def test_sqli_stacked_insert_does_not_create_row(self, client, db_session):
        """
        A stacked INSERT payload must not create a new project row.
        """
        # Baseline count
        before_count = len(client.get('/api/v1/projects').get_json()['projects'])

        payload = "x'; INSERT INTO projects (name, description, owner_id) VALUES ('injected_gs', 'injected', 1); --"
        response = client.get(f'/api/v1/search?q={payload}')
        assert response.status_code == 200

        # Ensure the stacked INSERT did not create a new row
        after = client.get('/api/v1/projects').get_json()['projects']
        names = [p['name'] for p in after]
        assert 'injected_gs' not in names
