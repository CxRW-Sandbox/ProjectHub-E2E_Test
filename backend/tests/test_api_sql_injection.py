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
# Helpers for /api/v1/tasks tests
# ---------------------------------------------------------------------------

def _create_v1_user(db_session, username, email, role='team_member'):
    """Create a user for /api/v1/tasks tests."""
    existing = db_session.query(User).filter_by(username=username).first()
    if existing:
        return existing
    user = User(username=username, email=email, role=role)
    user.set_password('testpass123')
    db_session.add(user)
    db_session.commit()
    return user


def _create_v1_project(db_session, name, owner_id):
    """Create a project for /api/v1/tasks tests."""
    from models import Project
    project = Project(name=name, description='Test project', owner_id=owner_id, is_public=False)
    db_session.add(project)
    db_session.commit()
    return project


def _create_v1_task(db_session, title, description, project_id, created_by, status='pending'):
    """Create a task directly in the test database for /api/v1/tasks tests."""
    from models import Task
    task = Task(
        title=title,
        description=description,
        project_id=project_id,
        created_by=created_by,
        status=status,
        priority='medium',
    )
    db_session.add(task)
    db_session.commit()
    return task


# ---------------------------------------------------------------------------
# Functional tests – /api/v1/tasks search works correctly after the fix
# ---------------------------------------------------------------------------

class TestGetTasksV1SearchFunctionality:
    """Verify that the search feature on /api/v1/tasks works correctly
    after the parameterized-query fix for CWE-89."""

    def test_get_tasks_no_search_returns_all(self, client, db_session):
        """Without a search parameter all tasks are returned."""
        user = _create_v1_user(db_session, 'v1_func_user1', 'v1func1@example.com')
        project = _create_v1_project(db_session, 'V1 Func Project 1', user.id)
        _create_v1_task(db_session, 'Task Alpha', 'first task', project.id, user.id)
        _create_v1_task(db_session, 'Task Beta', 'second task', project.id, user.id)

        response = client.get('/api/v1/tasks')
        assert response.status_code == 200

        data = response.get_json()
        assert 'tasks' in data
        assert len(data['tasks']) >= 2

    def test_get_tasks_search_by_title_returns_matching_task(self, client, db_session):
        """A search term matching a title returns only the matching task."""
        user = _create_v1_user(db_session, 'v1_func_user2', 'v1func2@example.com')
        project = _create_v1_project(db_session, 'V1 Func Project 2', user.id)
        _create_v1_task(db_session, 'NeedleInHaystack', 'some desc', project.id, user.id)
        _create_v1_task(db_session, 'Unrelated Task', 'other desc', project.id, user.id)

        response = client.get('/api/v1/tasks?search=NeedleInHaystack')
        assert response.status_code == 200

        data = response.get_json()
        titles = [t['title'] for t in data['tasks']]
        assert 'NeedleInHaystack' in titles
        assert 'Unrelated Task' not in titles

    def test_get_tasks_search_by_description_returns_matching_task(self, client, db_session):
        """A search term matching a description returns the correct task."""
        user = _create_v1_user(db_session, 'v1_func_user3', 'v1func3@example.com')
        project = _create_v1_project(db_session, 'V1 Func Project 3', user.id)
        _create_v1_task(db_session, 'Generic Title', 'unique_desc_keyword_xyz', project.id, user.id)
        _create_v1_task(db_session, 'Other Title', 'unrelated', project.id, user.id)

        response = client.get('/api/v1/tasks?search=unique_desc_keyword_xyz')
        assert response.status_code == 200

        data = response.get_json()
        titles = [t['title'] for t in data['tasks']]
        assert 'Generic Title' in titles
        assert 'Other Title' not in titles

    def test_get_tasks_search_partial_match(self, client, db_session):
        """Partial search term matches substrings in title or description."""
        user = _create_v1_user(db_session, 'v1_func_user4', 'v1func4@example.com')
        project = _create_v1_project(db_session, 'V1 Func Project 4', user.id)
        _create_v1_task(db_session, 'Implement Feature Z', 'feature description', project.id, user.id)

        response = client.get('/api/v1/tasks?search=Feature')
        assert response.status_code == 200

        data = response.get_json()
        titles = [t['title'] for t in data['tasks']]
        assert 'Implement Feature Z' in titles

    def test_get_tasks_search_no_match_returns_empty(self, client, db_session):
        """A search term that matches nothing returns an empty list."""
        user = _create_v1_user(db_session, 'v1_func_user5', 'v1func5@example.com')
        project = _create_v1_project(db_session, 'V1 Func Project 5', user.id)
        _create_v1_task(db_session, 'Normal Task V1', 'normal desc', project.id, user.id)

        response = client.get('/api/v1/tasks?search=zzznomatch_unique')
        assert response.status_code == 200

        data = response.get_json()
        assert data['tasks'] == []

    def test_get_tasks_search_combined_with_project_id(self, client, db_session):
        """search and project_id filters can be combined correctly."""
        user = _create_v1_user(db_session, 'v1_func_user6', 'v1func6@example.com')
        proj_a = _create_v1_project(db_session, 'V1 Combined Proj A', user.id)
        proj_b = _create_v1_project(db_session, 'V1 Combined Proj B', user.id)
        _create_v1_task(db_session, 'Widget Task V1 A', 'widget work', proj_a.id, user.id)
        _create_v1_task(db_session, 'Widget Task V1 B', 'widget work', proj_b.id, user.id)

        response = client.get(f'/api/v1/tasks?search=Widget&project_id={proj_a.id}')
        assert response.status_code == 200

        data = response.get_json()
        titles = [t['title'] for t in data['tasks']]
        assert 'Widget Task V1 A' in titles
        assert 'Widget Task V1 B' not in titles

    def test_get_tasks_empty_search_returns_all(self, client, db_session):
        """An empty search string falls through to the ORM path and returns all tasks."""
        user = _create_v1_user(db_session, 'v1_func_user7', 'v1func7@example.com')
        project = _create_v1_project(db_session, 'V1 Func Project 7', user.id)
        _create_v1_task(db_session, 'Empty Search Task', 'desc', project.id, user.id)

        response = client.get('/api/v1/tasks?search=')
        assert response.status_code == 200

        data = response.get_json()
        assert len(data['tasks']) >= 1

    def test_get_tasks_filter_by_project_id_only(self, client, db_session):
        """Filtering by project_id without search uses the ORM path correctly."""
        user = _create_v1_user(db_session, 'v1_func_user8', 'v1func8@example.com')
        proj_a = _create_v1_project(db_session, 'V1 ProjID Only A', user.id)
        proj_b = _create_v1_project(db_session, 'V1 ProjID Only B', user.id)
        _create_v1_task(db_session, 'Task in Proj A', 'desc', proj_a.id, user.id)
        _create_v1_task(db_session, 'Task in Proj B', 'desc', proj_b.id, user.id)

        response = client.get(f'/api/v1/tasks?project_id={proj_a.id}')
        assert response.status_code == 200

        data = response.get_json()
        titles = [t['title'] for t in data['tasks']]
        assert 'Task in Proj A' in titles
        assert 'Task in Proj B' not in titles

    def test_get_tasks_response_has_tasks_key(self, client, db_session):
        """Response always contains the 'tasks' key."""
        response = client.get('/api/v1/tasks')
        assert response.status_code == 200
        assert 'tasks' in response.get_json()


# ---------------------------------------------------------------------------
# Security tests – /api/v1/tasks SQL injection prevention (CWE-89)
# ---------------------------------------------------------------------------

class TestGetTasksV1SQLInjectionPrevention:
    """
    Verify that SQL injection payloads in the 'search', 'project_id', and
    'assigned_to' query parameters of /api/v1/tasks are treated as literal
    bound values and do NOT alter query structure or results.

    The fix uses SQLAlchemy text() with named parameters (:search, :project_id,
    :assigned_to) so user input is never interpolated into the SQL string.
    """

    def test_sqli_search_or_tautology_does_not_return_all_rows(self, client, db_session):
        """
        Classic OR-1=1 tautology in 'search' must NOT return all rows when no
        real match exists.

        Without the fix: the .format() call would embed the payload into the SQL,
        making the WHERE clause always true and returning every task.
        With the fix: the entire string is bound as a LIKE parameter literal and
        cannot escape the quoted value — only tasks whose title/description
        literally contain that text would match.
        """
        user = _create_v1_user(db_session, 'v1sqli_user1', 'v1sqli1@example.com')
        project = _create_v1_project(db_session, 'V1 SQLi Project 1', user.id)
        _create_v1_task(db_session, 'Secret V1 Task', 'confidential', project.id, user.id)

        payload = "' OR '1'='1"
        response = client.get(f'/api/v1/tasks?search={payload}')
        assert response.status_code == 200

        data = response.get_json()
        titles = [t['title'] for t in data['tasks']]
        assert 'Secret V1 Task' not in titles

    def test_sqli_search_single_quote_does_not_error(self, client, db_session):
        """A bare single-quote in the 'search' parameter must not raise a DB error."""
        response = client.get("/api/v1/tasks?search='")
        assert response.status_code == 200

    def test_sqli_search_double_quote_does_not_error(self, client, db_session):
        """A double-quote in the 'search' parameter must not raise a DB error."""
        response = client.get('/api/v1/tasks?search="')
        assert response.status_code == 200

    def test_sqli_search_semicolon_drop_table_does_not_affect_db(self, client, db_session):
        """
        A stacked DROP TABLE payload must not crash the server or destroy the
        tasks table — database integrity is preserved after the request.
        """
        user = _create_v1_user(db_session, 'v1sqli_user4', 'v1sqli4@example.com')
        project = _create_v1_project(db_session, 'V1 SQLi Project 4', user.id)
        _create_v1_task(db_session, 'V1 Persistent Task', 'should survive', project.id, user.id)

        payload = "x'; DROP TABLE tasks; --"
        response = client.get(f'/api/v1/tasks?search={payload}')
        # Must not crash
        assert response.status_code == 200

        # The tasks table must still be intact and contain our task
        get_all = client.get('/api/v1/tasks')
        assert get_all.status_code == 200
        titles = [t['title'] for t in get_all.get_json()['tasks']]
        assert 'V1 Persistent Task' in titles

    def test_sqli_search_comment_sequences_treated_literally(self, client, db_session):
        """SQL comment sequences (-- and #) in 'search' must be treated as literals."""
        for payload in ["--", "#", "' --", "admin'--"]:
            response = client.get(f'/api/v1/tasks?search={payload}')
            assert response.status_code == 200, f"Payload '{payload}' caused an error"

    def test_sqli_search_union_select_does_not_return_extra_rows(self, client, db_session):
        """
        A UNION SELECT payload in 'search' must not inject additional rows
        into the result set.

        Without the fix the UNION could append attacker-controlled columns to
        the result.  With the parameterized fix the entire string is the LIKE
        operand and matches nothing in the database.
        """
        user = _create_v1_user(db_session, 'v1sqli_user6', 'v1sqli6@example.com')
        project = _create_v1_project(db_session, 'V1 SQLi Project 6', user.id)
        _create_v1_task(db_session, 'Real Task V1', 'real desc', project.id, user.id)

        payload = "x' UNION SELECT 1,2,3,4,5,6,7,8,9,10 --"
        response = client.get(f'/api/v1/tasks?search={payload}')
        assert response.status_code == 200

        data = response.get_json()
        # The literal LIKE pattern won't match any real task
        assert data['tasks'] == []

    def test_sqli_search_encoded_quote_does_not_error(self, client, db_session):
        """URL-encoded single quote (%27) in 'search' must not cause a server error."""
        response = client.get('/api/v1/tasks?search=%27')
        assert response.status_code == 200

    def test_sqli_search_null_byte_does_not_error(self, client, db_session):
        """
        A null byte (%00) in the 'search' parameter must not cause a server error.
        The URL-encoded form is used here so no raw control byte is embedded in
        this source file.
        """
        response = client.get('/api/v1/tasks?search=%00')
        # Must not crash with 500; 400 is acceptable if the app rejects it
        assert response.status_code in (200, 400)

    def test_sqli_search_backslash_does_not_error(self, client, db_session):
        """Backslash sequences in 'search' must not cause a server error."""
        response = client.get("/api/v1/tasks?search=\\")
        assert response.status_code == 200

    def test_sqli_search_stacked_insert_does_not_create_row(self, client, db_session):
        """A stacked INSERT payload must not create a new task row."""
        before_count = len(client.get('/api/v1/tasks').get_json()['tasks'])

        payload = "'; INSERT INTO tasks (title, description, project_id, created_by, status, priority) VALUES ('injected_v1', 'injected', 1, 1, 'pending', 'low'); --"
        response = client.get(f'/api/v1/tasks?search={payload}')
        assert response.status_code == 200

        after = client.get('/api/v1/tasks').get_json()['tasks']
        titles = [t['title'] for t in after]
        assert 'injected_v1' not in titles

    def test_sqli_search_numeric_tautology_does_not_return_rows(self, client, db_session):
        """A numeric tautology (1=1) must not cause all rows to be returned."""
        user = _create_v1_user(db_session, 'v1sqli_user10', 'v1sqli10@example.com')
        project = _create_v1_project(db_session, 'V1 SQLi Project 10', user.id)
        _create_v1_task(db_session, 'Tautology Task V1', 'confidential', project.id, user.id)

        payload = "1' OR 1=1 --"
        response = client.get(f'/api/v1/tasks?search={payload}')
        assert response.status_code == 200

        data = response.get_json()
        titles = [t['title'] for t in data['tasks']]
        assert 'Tautology Task V1' not in titles

    def test_sqli_project_id_injection_does_not_return_extra_rows(self, client, db_session):
        """
        An injection payload in 'project_id' (combined with search) must not
        return rows from other projects.

        With the fix 'project_id' is bound as a named parameter (:project_id),
        so the injected string cannot alter the query logic.
        """
        user = _create_v1_user(db_session, 'v1sqli_user11', 'v1sqli11@example.com')
        project = _create_v1_project(db_session, 'V1 SQLi Project 11', user.id)
        _create_v1_task(db_session, 'CrossProject Task V1', 'desc', project.id, user.id)

        payload = "1 OR 1=1"
        response = client.get(f'/api/v1/tasks?search=CrossProject&project_id={payload}')
        # Must not return a 500; 200 (with filtered/no results) or 400 is acceptable
        assert response.status_code in (200, 400)

    def test_sqli_project_id_single_quote_combined_with_search_does_not_error(self, client, db_session):
        """A single-quote in 'project_id' (combined with search) must not trigger a DB error."""
        response = client.get("/api/v1/tasks?search=anything&project_id='")
        assert response.status_code in (200, 400)

    def test_sqli_assigned_to_injection_does_not_error(self, client, db_session):
        """An injection payload in 'assigned_to' (combined with search) must not error."""
        payload = "1 OR 1=1"
        response = client.get(f'/api/v1/tasks?search=anything&assigned_to={payload}')
        assert response.status_code in (200, 400)

    def test_sqli_search_special_chars_combo_does_not_error(self, client, db_session):
        """A combination of special SQL characters must not cause a server error."""
        payload = "'; SELECT * FROM tasks WHERE ''='"
        response = client.get(f'/api/v1/tasks?search={payload}')
        assert response.status_code == 200


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


# ---------------------------------------------------------------------------
# Helpers for /api/v1/projects/<project_id>/tasks tests
# ---------------------------------------------------------------------------

def _create_pt_user(db_session, username, email):
    """Create a user for project-tasks endpoint tests."""
    from models import User
    existing = db_session.query(User).filter_by(username=username).first()
    if existing:
        return existing
    user = User(username=username, email=email, role='team_member')
    user.set_password('ptpass123')
    db_session.add(user)
    db_session.commit()
    return user


def _create_pt_project(db_session, name, owner_id):
    """Create a project for project-tasks endpoint tests."""
    from models import Project
    project = Project(name=name, description='Test project', owner_id=owner_id, is_public=False)
    db_session.add(project)
    db_session.commit()
    return project


def _create_pt_task(db_session, title, description, project_id, created_by, status='pending'):
    """Create a task for project-tasks endpoint tests."""
    from models import Task
    task = Task(
        title=title,
        description=description,
        project_id=project_id,
        created_by=created_by,
        status=status,
        priority='medium',
    )
    db_session.add(task)
    db_session.commit()
    return task


# ---------------------------------------------------------------------------
# Functional tests – GET /api/v1/projects/<project_id>/tasks search works
# ---------------------------------------------------------------------------

class TestGetProjectTasksSearchFunctionality:
    """Verify that the search feature on /api/v1/projects/<id>/tasks works
    correctly after the parameterized-query fix (CWE-89)."""

    def test_no_search_returns_all_tasks_for_project(self, client, db_session):
        """Without a search parameter all tasks for the project are returned."""
        user = _create_pt_user(db_session, 'pt_func1', 'pt_func1@example.com')
        project = _create_pt_project(db_session, 'PT Func Project 1', user.id)
        _create_pt_task(db_session, 'Task One', 'first task', project.id, user.id)
        _create_pt_task(db_session, 'Task Two', 'second task', project.id, user.id)

        response = client.get(f'/api/v1/projects/{project.id}/tasks')
        assert response.status_code == 200

        data = response.get_json()
        assert 'tasks' in data
        assert len(data['tasks']) >= 2

    def test_search_by_title_returns_matching_task(self, client, db_session):
        """A search term matching a task title returns only the matching task."""
        user = _create_pt_user(db_session, 'pt_func2', 'pt_func2@example.com')
        project = _create_pt_project(db_session, 'PT Func Project 2', user.id)
        _create_pt_task(db_session, 'NeedleTask', 'haystack desc', project.id, user.id)
        _create_pt_task(db_session, 'OtherTask', 'unrelated desc', project.id, user.id)

        response = client.get(f'/api/v1/projects/{project.id}/tasks?search=NeedleTask')
        assert response.status_code == 200

        data = response.get_json()
        titles = [t['title'] for t in data['tasks']]
        assert 'NeedleTask' in titles
        assert 'OtherTask' not in titles

    def test_search_by_description_returns_matching_task(self, client, db_session):
        """A search term matching a description returns the correct task."""
        user = _create_pt_user(db_session, 'pt_func3', 'pt_func3@example.com')
        project = _create_pt_project(db_session, 'PT Func Project 3', user.id)
        _create_pt_task(db_session, 'Generic Title PT', 'unique_pt_keyword_xyz', project.id, user.id)
        _create_pt_task(db_session, 'Other Title PT', 'unrelated content', project.id, user.id)

        response = client.get(f'/api/v1/projects/{project.id}/tasks?search=unique_pt_keyword_xyz')
        assert response.status_code == 200

        data = response.get_json()
        titles = [t['title'] for t in data['tasks']]
        assert 'Generic Title PT' in titles
        assert 'Other Title PT' not in titles

    def test_search_partial_match_finds_task(self, client, db_session):
        """Partial search term matches substrings in title or description."""
        user = _create_pt_user(db_session, 'pt_func4', 'pt_func4@example.com')
        project = _create_pt_project(db_session, 'PT Func Project 4', user.id)
        _create_pt_task(db_session, 'Implement Feature ABC', 'feature work', project.id, user.id)

        response = client.get(f'/api/v1/projects/{project.id}/tasks?search=Feature')
        assert response.status_code == 200

        data = response.get_json()
        titles = [t['title'] for t in data['tasks']]
        assert 'Implement Feature ABC' in titles

    def test_search_no_match_returns_empty_list(self, client, db_session):
        """A search term that matches nothing returns an empty list."""
        user = _create_pt_user(db_session, 'pt_func5', 'pt_func5@example.com')
        project = _create_pt_project(db_session, 'PT Func Project 5', user.id)
        _create_pt_task(db_session, 'Normal Task PT', 'normal desc', project.id, user.id)

        response = client.get(f'/api/v1/projects/{project.id}/tasks?search=zzznomatch')
        assert response.status_code == 200

        data = response.get_json()
        assert data['tasks'] == []

    def test_search_does_not_return_tasks_from_other_projects(self, client, db_session):
        """Search results are scoped to the specified project_id."""
        user = _create_pt_user(db_session, 'pt_func6', 'pt_func6@example.com')
        proj_a = _create_pt_project(db_session, 'PT Proj A', user.id)
        proj_b = _create_pt_project(db_session, 'PT Proj B', user.id)
        _create_pt_task(db_session, 'Widget Task A', 'widget work', proj_a.id, user.id)
        _create_pt_task(db_session, 'Widget Task B', 'widget work', proj_b.id, user.id)

        response = client.get(f'/api/v1/projects/{proj_a.id}/tasks?search=Widget')
        assert response.status_code == 200

        data = response.get_json()
        titles = [t['title'] for t in data['tasks']]
        assert 'Widget Task A' in titles
        assert 'Widget Task B' not in titles

    def test_empty_search_returns_all_tasks_for_project(self, client, db_session):
        """An empty search string falls through to the ORM path and returns all tasks."""
        user = _create_pt_user(db_session, 'pt_func7', 'pt_func7@example.com')
        project = _create_pt_project(db_session, 'PT Func Project 7', user.id)
        _create_pt_task(db_session, 'Empty Search Task PT', 'desc', project.id, user.id)

        response = client.get(f'/api/v1/projects/{project.id}/tasks?search=')
        assert response.status_code == 200

        data = response.get_json()
        assert len(data['tasks']) >= 1

    def test_response_contains_tasks_key(self, client, db_session):
        """Response always contains the 'tasks' key."""
        user = _create_pt_user(db_session, 'pt_func8', 'pt_func8@example.com')
        project = _create_pt_project(db_session, 'PT Func Project 8', user.id)

        response = client.get(f'/api/v1/projects/{project.id}/tasks')
        assert response.status_code == 200
        assert 'tasks' in response.get_json()

    def test_nonexistent_project_returns_empty_tasks(self, client, db_session):
        """A project_id that doesn't exist returns an empty tasks list."""
        response = client.get('/api/v1/projects/999999/tasks')
        assert response.status_code == 200
        data = response.get_json()
        assert data['tasks'] == []


# ---------------------------------------------------------------------------
# Security tests – SQL injection payloads in search must be neutralised
# ---------------------------------------------------------------------------

class TestGetProjectTasksSQLInjectionPrevention:
    """
    Verify that SQL injection payloads in the 'search' parameter of
    GET /api/v1/projects/<project_id>/tasks are treated as literal strings
    and do NOT alter query structure or results (CWE-89 remediation).

    Prior to the fix, line 205 used an f-string to interpolate the untrusted
    'search' value directly into the SQL string passed to db.session.execute().
    The fix replaces that with a SQLAlchemy text() query using named parameters
    (:project_id, :search), so neither value is ever embedded in the SQL text.
    """

    def test_sqli_or_tautology_does_not_return_all_rows(self, client, db_session):
        """
        Classic OR-1=1 tautology must NOT return tasks from any project when
        no real match exists.

        Without the fix: the f-string would embed the payload and make the
        WHERE clause always true, returning every task in the project.
        With the fix: the entire string is bound as a LIKE parameter literal
        and can only match a task whose title/description contains that text.
        """
        user = _create_pt_user(db_session, 'pt_sqli1', 'pt_sqli1@example.com')
        project = _create_pt_project(db_session, 'PT SQLi Project 1', user.id)
        _create_pt_task(db_session, 'Secret PT Task', 'confidential', project.id, user.id)

        payload = "' OR '1'='1"
        response = client.get(f'/api/v1/projects/{project.id}/tasks?search={payload}')
        assert response.status_code == 200

        data = response.get_json()
        titles = [t['title'] for t in data['tasks']]
        assert 'Secret PT Task' not in titles

    def test_sqli_single_quote_does_not_error(self, client, db_session):
        """A bare single-quote in the search parameter must not raise a DB error."""
        user = _create_pt_user(db_session, 'pt_sqli2', 'pt_sqli2@example.com')
        project = _create_pt_project(db_session, 'PT SQLi Project 2', user.id)

        response = client.get(f"/api/v1/projects/{project.id}/tasks?search='")
        assert response.status_code == 200

    def test_sqli_double_quote_does_not_error(self, client, db_session):
        """A double-quote in the search parameter must not raise a DB error."""
        user = _create_pt_user(db_session, 'pt_sqli3', 'pt_sqli3@example.com')
        project = _create_pt_project(db_session, 'PT SQLi Project 3', user.id)

        response = client.get(f'/api/v1/projects/{project.id}/tasks?search="')
        assert response.status_code == 200

    def test_sqli_semicolon_drop_table_does_not_affect_db(self, client, db_session):
        """
        A stacked DROP TABLE payload must not crash the server or destroy the
        tasks table — database integrity must be preserved after the request.
        """
        user = _create_pt_user(db_session, 'pt_sqli4', 'pt_sqli4@example.com')
        project = _create_pt_project(db_session, 'PT SQLi Project 4', user.id)
        _create_pt_task(db_session, 'PT Persistent Task', 'should survive', project.id, user.id)

        payload = "x'; DROP TABLE tasks; --"
        response = client.get(f'/api/v1/projects/{project.id}/tasks?search={payload}')
        assert response.status_code == 200

        # The tasks table must still be intact and contain our task
        get_all = client.get(f'/api/v1/projects/{project.id}/tasks')
        assert get_all.status_code == 200
        titles = [t['title'] for t in get_all.get_json()['tasks']]
        assert 'PT Persistent Task' in titles

    def test_sqli_comment_sequences_treated_literally(self, client, db_session):
        """SQL comment sequences (-- and #) in the search must be treated as literals."""
        user = _create_pt_user(db_session, 'pt_sqli5', 'pt_sqli5@example.com')
        project = _create_pt_project(db_session, 'PT SQLi Project 5', user.id)
        _create_pt_task(db_session, 'CommentTestTask PT', 'desc', project.id, user.id)

        for payload in ["--", "#", "' --", "admin'--"]:
            response = client.get(
                f'/api/v1/projects/{project.id}/tasks?search={payload}'
            )
            assert response.status_code == 200, f"Payload '{payload}' caused an error"
            data = response.get_json()
            titles = [t['title'] for t in data['tasks']]
            assert 'CommentTestTask PT' not in titles, (
                f"Payload '{payload}' unexpectedly returned 'CommentTestTask PT'"
            )

    def test_sqli_union_select_does_not_return_extra_rows(self, client, db_session):
        """
        A UNION SELECT payload must not inject additional rows into the result.

        Without the fix the UNION could append attacker-controlled columns to
        the response.  With parameterized bindings the entire string is the LIKE
        operand and matches nothing in the database.
        """
        user = _create_pt_user(db_session, 'pt_sqli6', 'pt_sqli6@example.com')
        project = _create_pt_project(db_session, 'PT SQLi Project 6', user.id)
        _create_pt_task(db_session, 'Real PT Task', 'real desc', project.id, user.id)

        payload = "x' UNION SELECT 1,2,3,4,5,6,7,8,9,10 --"
        response = client.get(f'/api/v1/projects/{project.id}/tasks?search={payload}')
        assert response.status_code == 200

        data = response.get_json()
        # The literal LIKE pattern won't match any real task
        assert data['tasks'] == []

    def test_sqli_or_always_true_numeric_tautology(self, client, db_session):
        """Numeric tautology (1=1) must not cause all rows to be returned."""
        user = _create_pt_user(db_session, 'pt_sqli7', 'pt_sqli7@example.com')
        project = _create_pt_project(db_session, 'PT SQLi Project 7', user.id)
        _create_pt_task(db_session, 'Tautology PT Task', 'confidential', project.id, user.id)

        payload = "1' OR 1=1 --"
        response = client.get(f'/api/v1/projects/{project.id}/tasks?search={payload}')
        assert response.status_code == 200

        data = response.get_json()
        titles = [t['title'] for t in data['tasks']]
        assert 'Tautology PT Task' not in titles

    def test_sqli_encoded_quote_does_not_error(self, client, db_session):
        """
        URL-encoded single quote (%27) in the search parameter must not cause
        a server error.
        """
        user = _create_pt_user(db_session, 'pt_sqli8', 'pt_sqli8@example.com')
        project = _create_pt_project(db_session, 'PT SQLi Project 8', user.id)

        response = client.get(f'/api/v1/projects/{project.id}/tasks?search=%27')
        assert response.status_code == 200

    def test_sqli_backslash_does_not_error(self, client, db_session):
        """Backslash sequences in the search must not cause a server error."""
        user = _create_pt_user(db_session, 'pt_sqli9', 'pt_sqli9@example.com')
        project = _create_pt_project(db_session, 'PT SQLi Project 9', user.id)

        response = client.get(f'/api/v1/projects/{project.id}/tasks?search=\\')
        assert response.status_code == 200

    def test_sqli_null_byte_does_not_error(self, client, db_session):
        """
        A null byte (%00) in the search parameter must not cause a server error.
        Expressed as the URL-encoded form so no raw control byte is embedded in
        this source file.
        """
        user = _create_pt_user(db_session, 'pt_sqli10', 'pt_sqli10@example.com')
        project = _create_pt_project(db_session, 'PT SQLi Project 10', user.id)

        response = client.get(f'/api/v1/projects/{project.id}/tasks?search=%00')
        # Must not crash with 500; 400 is acceptable if the app rejects it
        assert response.status_code in (200, 400)

    def test_sqli_special_chars_combo_does_not_error(self, client, db_session):
        """A combination of special SQL characters must not cause a server error."""
        user = _create_pt_user(db_session, 'pt_sqli11', 'pt_sqli11@example.com')
        project = _create_pt_project(db_session, 'PT SQLi Project 11', user.id)

        payload = "'; SELECT * FROM tasks WHERE ''='"
        response = client.get(f'/api/v1/projects/{project.id}/tasks?search={payload}')
        assert response.status_code == 200

    def test_sqli_stacked_insert_does_not_create_row(self, client, db_session):
        """
        A stacked INSERT payload must not create a new task row.

        Without the fix: SQLite's multi-statement execution could insert an
        attacker-controlled task.  With parameterized queries the stacked
        statement cannot be parsed out of the bound value.
        """
        user = _create_pt_user(db_session, 'pt_sqli12', 'pt_sqli12@example.com')
        project = _create_pt_project(db_session, 'PT SQLi Project 12', user.id)

        payload = (
            "'; INSERT INTO tasks "
            "(title, description, project_id, created_by, status, priority) "
            "VALUES ('injected_pt', 'injected', 1, 1, 'pending', 'low'); --"
        )
        response = client.get(f'/api/v1/projects/{project.id}/tasks?search={payload}')
        assert response.status_code == 200

        # Verify the injected task was not created
        all_tasks = client.get(f'/api/v1/projects/{project.id}/tasks').get_json()['tasks']
        titles = [t['title'] for t in all_tasks]
        assert 'injected_pt' not in titles

    def test_sqli_cross_project_traversal_via_search(self, client, db_session):
        """
        An injection payload attempting to remove the project_id constraint
        must not return tasks from other projects.

        Without the fix: a payload like  x%' OR project_id = <other_id> --
        embedded in the f-string would extend the WHERE clause and leak tasks
        from any project.  With parameterized queries the entire payload is
        bound as a LIKE literal and the project_id constraint is always enforced
        via its own separate named parameter.
        """
        user = _create_pt_user(db_session, 'pt_sqli13', 'pt_sqli13@example.com')
        proj_a = _create_pt_project(db_session, 'PT Proj A Traversal', user.id)
        proj_b = _create_pt_project(db_session, 'PT Proj B Traversal', user.id)
        _create_pt_task(db_session, 'Task Only In Proj B', 'confidential', proj_b.id, user.id)

        # Try to escape the project scope by injecting into the search param
        payload = f"x%' OR project_id = {proj_b.id} --"
        response = client.get(f'/api/v1/projects/{proj_a.id}/tasks?search={payload}')
        assert response.status_code == 200

        data = response.get_json()
        titles = [t['title'] for t in data['tasks']]
        assert 'Task Only In Proj B' not in titles
