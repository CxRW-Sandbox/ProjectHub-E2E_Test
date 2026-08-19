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
# Helpers for /api/v1/tasks tests (get_tasks_api)
# ---------------------------------------------------------------------------

def _create_task_for_api(db_session, title, description, project_id, created_by,
                          status='pending', assigned_to=None):
    """Create a Task row directly in the test database."""
    from models import Task
    task = Task(
        title=title,
        description=description,
        project_id=project_id,
        created_by=created_by,
        status=status,
        priority='medium',
        assigned_to=assigned_to,
    )
    db_session.add(task)
    db_session.commit()
    return task


# ---------------------------------------------------------------------------
# Functional tests – /api/v1/tasks search works correctly after fix
# ---------------------------------------------------------------------------

class TestGetTasksApiSearchFunctionality:
    """
    Verify that the search feature on /api/v1/tasks (get_tasks_api) works
    correctly after the parameterized-query fix (CWE-89).

    The old implementation built raw SQL via .format() string interpolation.
    The fix replaces it with SQLAlchemy ORM filter() / .like() calls so that
    every user-supplied value is bound as a parameter and never interpreted
    as SQL syntax.
    """

    def test_get_tasks_no_search_returns_all(self, client, db_session):
        """Without a search parameter all tasks are returned."""
        owner = _create_owner(db_session, 'tasks_func_owner', 'tasks_func@example.com')
        project = _create_project(db_session, 'Tasks Func Project', 'desc', owner.id)
        _create_task_for_api(db_session, 'Alpha Task', 'first', project.id, owner.id)
        _create_task_for_api(db_session, 'Beta Task', 'second', project.id, owner.id)

        response = client.get('/api/v1/tasks')
        assert response.status_code == 200

        data = response.get_json()
        assert 'tasks' in data
        assert len(data['tasks']) >= 2

    def test_get_tasks_search_by_title(self, client, db_session):
        """Search term matching a task title returns only matching tasks."""
        owner = _create_owner(db_session, 'tasks_func_owner2', 'tasks_func2@example.com')
        project = _create_project(db_session, 'Tasks Func Project 2', 'desc', owner.id)
        _create_task_for_api(db_session, 'Unique Needle Task', 'some desc', project.id, owner.id)
        _create_task_for_api(db_session, 'Other Task', 'other desc', project.id, owner.id)

        response = client.get('/api/v1/tasks?search=Needle')
        assert response.status_code == 200

        data = response.get_json()
        titles = [t['title'] for t in data['tasks']]
        assert 'Unique Needle Task' in titles
        assert 'Other Task' not in titles

    def test_get_tasks_search_by_description(self, client, db_session):
        """Search term matching a task description returns that task."""
        owner = _create_owner(db_session, 'tasks_func_owner3', 'tasks_func3@example.com')
        project = _create_project(db_session, 'Tasks Func Project 3', 'desc', owner.id)
        _create_task_for_api(db_session, 'Plain Title', 'contains_searchable_kw', project.id, owner.id)
        _create_task_for_api(db_session, 'Another Title', 'unrelated', project.id, owner.id)

        response = client.get('/api/v1/tasks?search=searchable_kw')
        assert response.status_code == 200

        data = response.get_json()
        titles = [t['title'] for t in data['tasks']]
        assert 'Plain Title' in titles
        assert 'Another Title' not in titles

    def test_get_tasks_search_partial_match(self, client, db_session):
        """Partial search terms match substrings in title or description."""
        owner = _create_owner(db_session, 'tasks_func_owner4', 'tasks_func4@example.com')
        project = _create_project(db_session, 'Tasks Func Project 4', 'desc', owner.id)
        _create_task_for_api(db_session, 'Implement Feature X', 'feature desc', project.id, owner.id)

        response = client.get('/api/v1/tasks?search=Feature')
        assert response.status_code == 200

        data = response.get_json()
        titles = [t['title'] for t in data['tasks']]
        assert 'Implement Feature X' in titles

    def test_get_tasks_search_no_match_returns_empty(self, client, db_session):
        """A search term that matches nothing returns an empty list."""
        owner = _create_owner(db_session, 'tasks_func_owner5', 'tasks_func5@example.com')
        project = _create_project(db_session, 'Tasks Func Project 5', 'desc', owner.id)
        _create_task_for_api(db_session, 'Normal Task', 'normal desc', project.id, owner.id)

        response = client.get('/api/v1/tasks?search=zzznomatch')
        assert response.status_code == 200

        data = response.get_json()
        assert data['tasks'] == []

    def test_get_tasks_filtered_by_project_id(self, client, db_session):
        """Filtering by project_id returns only tasks from that project."""
        owner = _create_owner(db_session, 'tasks_func_owner6', 'tasks_func6@example.com')
        project_a = _create_project(db_session, 'Tasks Project A', 'desc', owner.id)
        project_b = _create_project(db_session, 'Tasks Project B', 'desc', owner.id)
        _create_task_for_api(db_session, 'Task in A', 'desc', project_a.id, owner.id)
        _create_task_for_api(db_session, 'Task in B', 'desc', project_b.id, owner.id)

        response = client.get(f'/api/v1/tasks?project_id={project_a.id}')
        assert response.status_code == 200

        data = response.get_json()
        titles = [t['title'] for t in data['tasks']]
        assert 'Task in A' in titles
        assert 'Task in B' not in titles

    def test_get_tasks_search_combined_with_project_id(self, client, db_session):
        """search and project_id filters can be combined correctly."""
        owner = _create_owner(db_session, 'tasks_func_owner7', 'tasks_func7@example.com')
        project_a = _create_project(db_session, 'Combined Tasks Project A', 'desc', owner.id)
        project_b = _create_project(db_session, 'Combined Tasks Project B', 'desc', owner.id)
        _create_task_for_api(db_session, 'Widget Task A', 'widget work', project_a.id, owner.id)
        _create_task_for_api(db_session, 'Widget Task B', 'widget work', project_b.id, owner.id)

        response = client.get(f'/api/v1/tasks?search=Widget&project_id={project_a.id}')
        assert response.status_code == 200

        data = response.get_json()
        titles = [t['title'] for t in data['tasks']]
        assert 'Widget Task A' in titles
        assert 'Widget Task B' not in titles

    def test_get_tasks_response_contains_tasks_key(self, client, db_session):
        """Response always contains the 'tasks' key."""
        response = client.get('/api/v1/tasks')
        assert response.status_code == 200
        assert 'tasks' in response.get_json()

    def test_get_tasks_response_task_has_expected_fields(self, client, db_session):
        """Each task in the response has the expected fields from Task.to_dict()."""
        owner = _create_owner(db_session, 'tasks_func_owner8', 'tasks_func8@example.com')
        project = _create_project(db_session, 'Field Check Project', 'desc', owner.id)
        _create_task_for_api(db_session, 'Field Check Task', 'checking fields', project.id, owner.id)

        response = client.get('/api/v1/tasks?search=Field Check Task')
        assert response.status_code == 200

        data = response.get_json()
        assert len(data['tasks']) >= 1
        task = data['tasks'][0]
        for field in ('id', 'title', 'description', 'project_id', 'status', 'priority'):
            assert field in task, f"Expected field '{field}' missing from task dict"


# ---------------------------------------------------------------------------
# Security tests – SQL injection payloads in /api/v1/tasks must be rejected
# ---------------------------------------------------------------------------

class TestGetTasksApiSQLInjectionPrevention:
    """
    Verify that SQL injection payloads in the 'search', 'project_id', and
    'assigned_to' query parameters of /api/v1/tasks are treated as literal
    strings and do not affect the query structure or results (CWE-89).

    The taint flow being tested:
      SOURCE  → request.args.get('search', '')       [line 218]
      SINK    → db.session.execute(text(query))       [was line 228, now eliminated]

    The fix replaces the string-format SQL construction with SQLAlchemy ORM
    filter() / .like() calls, which bind all values as named parameters so
    the database driver never interprets them as SQL syntax.
    """

    def test_sqli_search_or_tautology_does_not_return_all_rows(self, client, db_session):
        """
        Classic OR 1=1 tautology in 'search' must NOT return all rows when no
        real match exists.

        Without parameterization  ' OR '1'='1  would expand to a tautology and
        match every row.  With the ORM fix the string is the bound LIKE value.
        """
        owner = _create_owner(db_session, 'tasks_sqli_owner1', 'tasks_sqli1@example.com')
        project = _create_project(db_session, 'SQLi Tasks Project 1', 'desc', owner.id)
        _create_task_for_api(db_session, 'Secret Task', 'confidential', project.id, owner.id)

        payload = "' OR '1'='1"
        response = client.get(f'/api/v1/tasks?search={payload}')
        assert response.status_code == 200

        data = response.get_json()
        titles = [t['title'] for t in data['tasks']]
        assert 'Secret Task' not in titles

    def test_sqli_search_single_quote_does_not_error(self, client, db_session):
        """A bare single-quote in 'search' must not raise a DB error."""
        response = client.get("/api/v1/tasks?search='")
        assert response.status_code == 200

    def test_sqli_search_double_quote_does_not_error(self, client, db_session):
        """A double-quote in 'search' must not raise a DB error."""
        response = client.get('/api/v1/tasks?search="')
        assert response.status_code == 200

    def test_sqli_search_semicolon_drop_table_does_not_affect_db(self, client, db_session):
        """
        A semicolon followed by DROP TABLE must not cause any error or affect
        the database — the tasks table must remain intact.
        """
        owner = _create_owner(db_session, 'tasks_sqli_owner2', 'tasks_sqli2@example.com')
        project = _create_project(db_session, 'SQLi Tasks Project 2', 'desc', owner.id)
        _create_task_for_api(db_session, 'Persistent Task', 'must survive', project.id, owner.id)

        payload = "x'; DROP TABLE tasks; --"
        response = client.get(f'/api/v1/tasks?search={payload}')
        assert response.status_code == 200

        # The tasks table must still exist and the task is still there
        get_all = client.get('/api/v1/tasks')
        assert get_all.status_code == 200
        titles = [t['title'] for t in get_all.get_json()['tasks']]
        assert 'Persistent Task' in titles

    def test_sqli_search_comment_sequences_treated_literally(self, client, db_session):
        """SQL comment sequences (-- and #) in 'search' must be treated as literals."""
        owner = _create_owner(db_session, 'tasks_sqli_owner3', 'tasks_sqli3@example.com')
        project = _create_project(db_session, 'SQLi Tasks Project 3', 'desc', owner.id)
        _create_task_for_api(db_session, 'Comment Test Task', 'desc', project.id, owner.id)

        for payload in ["--", "#", "' --", "admin'--"]:
            response = client.get(f'/api/v1/tasks?search={payload}')
            assert response.status_code == 200, f"Payload '{payload}' caused an error"
            data = response.get_json()
            titles = [t['title'] for t in data['tasks']]
            assert 'Comment Test Task' not in titles, (
                f"Payload '{payload}' unexpectedly returned 'Comment Test Task'"
            )

    def test_sqli_search_union_select_does_not_return_extra_rows(self, client, db_session):
        """
        A UNION SELECT payload in 'search' must not inject additional rows.
        The parameterized ORM LIKE treats the whole string as a literal value.
        """
        owner = _create_owner(db_session, 'tasks_sqli_owner4', 'tasks_sqli4@example.com')

        payload = "x' UNION SELECT 1,2,3,4,5,6,7,8,9,10 --"
        response = client.get(f'/api/v1/tasks?search={payload}')
        assert response.status_code == 200

        data = response.get_json()
        # No real tasks should match the literal LIKE pattern
        assert data['tasks'] == []

    def test_sqli_search_stacked_queries_do_not_insert_row(self, client, db_session):
        """A stacked INSERT query in 'search' must not create a new task row."""
        owner = _create_owner(db_session, 'tasks_sqli_owner5', 'tasks_sqli5@example.com')
        project = _create_project(db_session, 'SQLi Tasks Project 5', 'desc', owner.id)

        before_count = len(client.get('/api/v1/tasks').get_json()['tasks'])

        payload = (
            "x'; INSERT INTO tasks (title, description, project_id, created_by, "
            "status, priority) VALUES ('injected', 'injected', 1, 1, 'pending', 'low'); --"
        )
        response = client.get(f'/api/v1/tasks?search={payload}')
        assert response.status_code == 200

        after = client.get('/api/v1/tasks').get_json()['tasks']
        titles = [t['title'] for t in after]
        assert 'injected' not in titles

    def test_sqli_search_encoded_quote_does_not_error(self, client, db_session):
        """URL-encoded single quote (%27) in 'search' must not cause a server error."""
        response = client.get('/api/v1/tasks?search=%27')
        assert response.status_code == 200

    def test_sqli_search_null_byte_does_not_error(self, client, db_session):
        """
        A null byte (%00) in 'search' must not cause a server error.
        The URL-encoded form is used here so no raw control byte is embedded
        in this source file.
        """
        response = client.get('/api/v1/tasks?search=%00')
        assert response.status_code in (200, 400)

    def test_sqli_search_backslash_does_not_error(self, client, db_session):
        """Backslash sequences in 'search' must not cause a server error."""
        response = client.get("/api/v1/tasks?search=\\")
        assert response.status_code == 200

    def test_sqli_search_special_chars_combo_does_not_error(self, client, db_session):
        """A combination of special characters must not cause a server error."""
        payload = "'; SELECT * FROM tasks WHERE ''='"
        response = client.get(f'/api/v1/tasks?search={payload}')
        assert response.status_code == 200

    def test_sqli_search_numeric_tautology_does_not_return_all_rows(self, client, db_session):
        """
        Numeric tautology payload in 'search' must not return rows that do not
        literally contain that string.
        """
        owner = _create_owner(db_session, 'tasks_sqli_owner6', 'tasks_sqli6@example.com')
        project = _create_project(db_session, 'SQLi Tasks Project 6', 'desc', owner.id)
        _create_task_for_api(db_session, 'Numeric Tautology Task', 'desc', project.id, owner.id)

        payload = "1' OR 1=1 --"
        response = client.get(f'/api/v1/tasks?search={payload}')
        assert response.status_code == 200

        data = response.get_json()
        titles = [t['title'] for t in data['tasks']]
        assert 'Numeric Tautology Task' not in titles

    def test_sqli_project_id_non_integer_does_not_error(self, client, db_session):
        """
        A non-integer 'project_id' (e.g. injection payload) must not cause a
        server error.  The ORM filter_by safely handles non-integer values.
        """
        payload = "1 OR 1=1"
        response = client.get(f'/api/v1/tasks?project_id={payload}')
        # Should not return a 500 — 200 (no rows) or 400 (type error) is acceptable
        assert response.status_code in (200, 400)

    def test_sqli_project_id_single_quote_does_not_error(self, client, db_session):
        """A single-quote in 'project_id' must not trigger a DB error."""
        response = client.get("/api/v1/tasks?project_id='")
        assert response.status_code in (200, 400)

    def test_sqli_project_id_union_payload_does_not_return_extra_rows(self, client, db_session):
        """
        A UNION SELECT payload in 'project_id' must not inject additional rows.
        """
        owner = _create_owner(db_session, 'tasks_sqli_owner7', 'tasks_sqli7@example.com')
        project = _create_project(db_session, 'SQLi Tasks Project 7', 'desc', owner.id)
        _create_task_for_api(db_session, 'Real Task 7', 'real desc', project.id, owner.id)

        payload = "1 UNION SELECT 1,2,3,4,5,6,7,8,9,10 --"
        response = client.get(f'/api/v1/tasks?project_id={payload}')
        assert response.status_code in (200, 400)
        if response.status_code == 200:
            data = response.get_json()
            # All returned tasks must be real Task model instances (have valid int IDs)
            for task in data['tasks']:
                assert isinstance(task['id'], int)

    def test_sqli_assigned_to_non_integer_does_not_error(self, client, db_session):
        """
        A non-integer 'assigned_to' (e.g. injection payload) must not cause a
        server error.  The ORM filter_by safely handles non-integer values.
        """
        payload = "1 OR 1=1"
        response = client.get(f'/api/v1/tasks?assigned_to={payload}')
        assert response.status_code in (200, 400)

    def test_sqli_assigned_to_single_quote_does_not_error(self, client, db_session):
        """A single-quote in 'assigned_to' must not trigger a DB error."""
        response = client.get("/api/v1/tasks?assigned_to='")
        assert response.status_code in (200, 400)

    def test_sqli_search_and_project_id_combined_payload(self, client, db_session):
        """
        Injection payloads in both 'search' and 'project_id' simultaneously
        must not cause an error or return unexpected rows.
        """
        owner = _create_owner(db_session, 'tasks_sqli_owner8', 'tasks_sqli8@example.com')
        project = _create_project(db_session, 'SQLi Tasks Project 8', 'desc', owner.id)
        _create_task_for_api(db_session, 'Combined Payload Task', 'desc', project.id, owner.id)

        search_payload = "' OR '1'='1"
        pid_payload = "1 OR 1=1"
        response = client.get(
            f'/api/v1/tasks?search={search_payload}&project_id={pid_payload}'
        )
        assert response.status_code in (200, 400)
        if response.status_code == 200:
            data = response.get_json()
            titles = [t['title'] for t in data['tasks']]
            assert 'Combined Payload Task' not in titles
