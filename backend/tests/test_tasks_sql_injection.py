"""
Security tests for SQL injection prevention in /api/tasks endpoint.

These tests verify that the get_tasks endpoint correctly uses SQLAlchemy ORM
parameterized queries instead of raw string-formatted SQL, preventing SQL
injection attacks (CWE-89).

The vulnerability existed in get_tasks() where user-supplied 'search' and
'project_id' query parameters were directly interpolated into a SQL string
that was then executed via db.session.execute(text(query)).

The fix replaces the raw SQL construction with SQLAlchemy ORM filter() calls
using .like() / db.or_(), which bind all values as parameters and never
interpret them as SQL syntax.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import db, User, Project, Task


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


def _create_project(db_session, name, owner_id):
    """Create a project directly in the test database."""
    project = Project(name=name, description='Test project', owner_id=owner_id, is_public=False)
    db_session.add(project)
    db_session.commit()
    return project


def _create_task(db_session, title, description, project_id, created_by, status='pending'):
    """Create a task directly in the test database."""
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


def _auth_headers(app, user):
    """Return Bearer token headers for the given user."""
    with app.app_context():
        from auth import generate_token
        token = generate_token(user.id, user.username)
        return {'Authorization': f'Bearer {token}'}


# ---------------------------------------------------------------------------
# Functional tests – verify that legitimate searches still work correctly
# ---------------------------------------------------------------------------

class TestGetTasksSearchFunctionality:
    """Verify that the search feature works correctly after the parameterization fix."""

    def test_get_tasks_no_search_returns_all(self, client, app, db_session):
        """Without a search parameter all tasks for the user are returned."""
        user = _create_user(db_session, 'func_user1', 'func1@example.com')
        project = _create_project(db_session, 'Func Project 1', user.id)
        _create_task(db_session, 'Alpha Task', 'first task', project.id, user.id)
        _create_task(db_session, 'Beta Task', 'second task', project.id, user.id)
        headers = _auth_headers(app, user)

        response = client.get('/api/tasks', headers=headers)
        assert response.status_code == 200

        data = response.get_json()
        assert 'tasks' in data
        assert len(data['tasks']) >= 2

    def test_get_tasks_search_by_title(self, client, app, db_session):
        """Search term matching a task title returns only matching tasks."""
        user = _create_user(db_session, 'func_user2', 'func2@example.com')
        project = _create_project(db_session, 'Func Project 2', user.id)
        _create_task(db_session, 'Unique Needle Task', 'some desc', project.id, user.id)
        _create_task(db_session, 'Other Task', 'other desc', project.id, user.id)
        headers = _auth_headers(app, user)

        response = client.get('/api/tasks?search=Needle', headers=headers)
        assert response.status_code == 200

        data = response.get_json()
        titles = [t['title'] for t in data['tasks']]
        assert 'Unique Needle Task' in titles
        assert 'Other Task' not in titles

    def test_get_tasks_search_by_description(self, client, app, db_session):
        """Search term matching a task description returns that task."""
        user = _create_user(db_session, 'func_user3', 'func3@example.com')
        project = _create_project(db_session, 'Func Project 3', user.id)
        _create_task(db_session, 'Plain Title', 'contains_searchable_keyword', project.id, user.id)
        _create_task(db_session, 'Another Title', 'unrelated description', project.id, user.id)
        headers = _auth_headers(app, user)

        response = client.get('/api/tasks?search=searchable_keyword', headers=headers)
        assert response.status_code == 200

        data = response.get_json()
        titles = [t['title'] for t in data['tasks']]
        assert 'Plain Title' in titles
        assert 'Another Title' not in titles

    def test_get_tasks_search_partial_match(self, client, app, db_session):
        """Partial search terms match substrings in title or description."""
        user = _create_user(db_session, 'func_user4', 'func4@example.com')
        project = _create_project(db_session, 'Func Project 4', user.id)
        _create_task(db_session, 'Implement Feature X', 'feature description', project.id, user.id)
        headers = _auth_headers(app, user)

        response = client.get('/api/tasks?search=Feature', headers=headers)
        assert response.status_code == 200

        data = response.get_json()
        titles = [t['title'] for t in data['tasks']]
        assert 'Implement Feature X' in titles

    def test_get_tasks_search_no_match_returns_empty(self, client, app, db_session):
        """A search term that matches nothing returns an empty list."""
        user = _create_user(db_session, 'func_user5', 'func5@example.com')
        project = _create_project(db_session, 'Func Project 5', user.id)
        _create_task(db_session, 'Normal Task', 'normal desc', project.id, user.id)
        headers = _auth_headers(app, user)

        response = client.get('/api/tasks?search=zzznomatch', headers=headers)
        assert response.status_code == 200

        data = response.get_json()
        assert data['tasks'] == []

    def test_get_tasks_filtered_by_project_id(self, client, app, db_session):
        """Filtering by project_id returns only tasks from that project."""
        user = _create_user(db_session, 'func_user6', 'func6@example.com')
        project_a = _create_project(db_session, 'Project A', user.id)
        project_b = _create_project(db_session, 'Project B', user.id)
        _create_task(db_session, 'Task in A', 'desc', project_a.id, user.id)
        _create_task(db_session, 'Task in B', 'desc', project_b.id, user.id)
        headers = _auth_headers(app, user)

        response = client.get(f'/api/tasks?project_id={project_a.id}', headers=headers)
        assert response.status_code == 200

        data = response.get_json()
        titles = [t['title'] for t in data['tasks']]
        assert 'Task in A' in titles
        assert 'Task in B' not in titles

    def test_get_tasks_search_combined_with_project_id(self, client, app, db_session):
        """search and project_id filters can be combined correctly."""
        user = _create_user(db_session, 'func_user7', 'func7@example.com')
        project_a = _create_project(db_session, 'Combined Project A', user.id)
        project_b = _create_project(db_session, 'Combined Project B', user.id)
        _create_task(db_session, 'Widget Task', 'widget work', project_a.id, user.id)
        _create_task(db_session, 'Widget Task B', 'widget work', project_b.id, user.id)
        headers = _auth_headers(app, user)

        response = client.get(
            f'/api/tasks?search=Widget&project_id={project_a.id}',
            headers=headers,
        )
        assert response.status_code == 200

        data = response.get_json()
        titles = [t['title'] for t in data['tasks']]
        assert 'Widget Task' in titles
        assert 'Widget Task B' not in titles

    def test_get_tasks_requires_authentication(self, client):
        """Endpoint must return 401 when no auth token is provided."""
        response = client.get('/api/tasks')
        assert response.status_code == 401


# ---------------------------------------------------------------------------
# Security tests – SQL injection payloads must NOT alter query behaviour
# ---------------------------------------------------------------------------

class TestGetTasksSQLInjectionPrevention:
    """
    Verify that SQL injection payloads in the 'search' and 'project_id'
    query parameters are treated as literal strings and do not affect the
    query's structure or results.

    With the parameterized ORM fix each value is bound as a query parameter,
    so none of these should raise a database error or return unexpected rows.
    """

    def test_sqli_search_or_tautology_does_not_return_all_rows(self, client, app, db_session):
        """
        Classic OR 1=1 tautology in 'search' must NOT return all rows when no
        real match exists.

        Without parameterization  ' OR '1'='1  would match every row.
        With the ORM fix the entire string is the LIKE pattern, so it only
        matches a title/description that literally contains that text.
        """
        user = _create_user(db_session, 'sqli_user1', 'sqli1@example.com')
        project = _create_project(db_session, 'SQLi Project 1', user.id)
        _create_task(db_session, 'Secret Task', 'confidential', project.id, user.id)
        headers = _auth_headers(app, user)

        payload = "' OR '1'='1"
        response = client.get(f'/api/tasks?search={payload}', headers=headers)
        assert response.status_code == 200

        data = response.get_json()
        titles = [t['title'] for t in data['tasks']]
        assert 'Secret Task' not in titles

    def test_sqli_search_single_quote_does_not_error(self, client, app, db_session):
        """A bare single-quote in the 'search' parameter must not raise a DB error."""
        user = _create_user(db_session, 'sqli_user2', 'sqli2@example.com')
        headers = _auth_headers(app, user)

        response = client.get("/api/tasks?search='", headers=headers)
        assert response.status_code == 200

    def test_sqli_search_double_quote_does_not_error(self, client, app, db_session):
        """A double-quote in the 'search' parameter must not raise a DB error."""
        user = _create_user(db_session, 'sqli_user3', 'sqli3@example.com')
        headers = _auth_headers(app, user)

        response = client.get('/api/tasks?search="', headers=headers)
        assert response.status_code == 200

    def test_sqli_search_semicolon_drop_table_does_not_affect_db(self, client, app, db_session):
        """
        A semicolon followed by DROP TABLE must not cause any error or affect
        the database — the tasks table must remain intact.
        """
        user = _create_user(db_session, 'sqli_user4', 'sqli4@example.com')
        project = _create_project(db_session, 'SQLi Project 4', user.id)
        _create_task(db_session, 'Persistent Task', 'should survive', project.id, user.id)
        headers = _auth_headers(app, user)

        payload = "x'; DROP TABLE tasks; --"
        response = client.get(f'/api/tasks?search={payload}', headers=headers)
        # Must not crash
        assert response.status_code == 200

        # The tasks table must still exist and the task is still there
        get_all = client.get('/api/tasks', headers=headers)
        assert get_all.status_code == 200
        titles = [t['title'] for t in get_all.get_json()['tasks']]
        assert 'Persistent Task' in titles

    def test_sqli_search_comment_sequences_treated_literally(self, client, app, db_session):
        """SQL comment sequences (-- and #) in the 'search' must be treated as literals."""
        user = _create_user(db_session, 'sqli_user5', 'sqli5@example.com')
        headers = _auth_headers(app, user)

        for payload in ["--", "#", "' --", "admin'--"]:
            response = client.get(f'/api/tasks?search={payload}', headers=headers)
            assert response.status_code == 200, f"Payload '{payload}' caused an error"

    def test_sqli_search_union_select_does_not_return_extra_rows(self, client, app, db_session):
        """
        A UNION SELECT payload in 'search' must not inject additional rows.
        The parameterized LIKE treats the whole string as a literal value.
        """
        user = _create_user(db_session, 'sqli_user6', 'sqli6@example.com')
        headers = _auth_headers(app, user)

        payload = "x' UNION SELECT 1,2,3,4,5,6,7,8,9,10 --"
        response = client.get(f'/api/tasks?search={payload}', headers=headers)
        assert response.status_code == 200

        data = response.get_json()
        # No real tasks match this pattern
        assert data['tasks'] == []

    def test_sqli_search_encoded_quote_does_not_error(self, client, app, db_session):
        """URL-encoded single quote (%27) in 'search' must not cause a server error."""
        user = _create_user(db_session, 'sqli_user7', 'sqli7@example.com')
        headers = _auth_headers(app, user)

        response = client.get('/api/tasks?search=%27', headers=headers)
        assert response.status_code == 200

    def test_sqli_search_null_byte_does_not_error(self, client, app, db_session):
        """
        A null byte (%00) in the 'search' parameter must not cause a server
        error.  The URL-encoded form is used here so no raw control byte is
        embedded in this source file.
        """
        user = _create_user(db_session, 'sqli_user8', 'sqli8@example.com')
        headers = _auth_headers(app, user)

        response = client.get('/api/tasks?search=%00', headers=headers)
        assert response.status_code in (200, 400)

    def test_sqli_search_backslash_does_not_error(self, client, app, db_session):
        """Backslash sequences in 'search' must not cause a server error."""
        user = _create_user(db_session, 'sqli_user9', 'sqli9@example.com')
        headers = _auth_headers(app, user)

        response = client.get("/api/tasks?search=\\", headers=headers)
        assert response.status_code == 200

    def test_sqli_search_stacked_queries_do_not_execute(self, client, app, db_session):
        """A stacked query payload must not alter the database or cause an error."""
        user = _create_user(db_session, 'sqli_user10', 'sqli10@example.com')
        project = _create_project(db_session, 'SQLi Project 10', user.id)
        _create_task(db_session, 'Stacked Query Task', 'must survive', project.id, user.id)
        headers = _auth_headers(app, user)

        payload = "'; SELECT * FROM users WHERE ''='"
        response = client.get(f'/api/tasks?search={payload}', headers=headers)
        assert response.status_code == 200

        # The task is still retrievable — the database was not altered
        get_all = client.get('/api/tasks', headers=headers)
        assert get_all.status_code == 200
        titles = [t['title'] for t in get_all.get_json()['tasks']]
        assert 'Stacked Query Task' in titles

    def test_sqli_project_id_non_integer_does_not_error(self, client, app, db_session):
        """
        A non-integer 'project_id' (e.g. injection payload) must not cause a
        server error.  The ORM filter_by will receive a string value and
        SQLAlchemy handles type coercion safely.
        """
        user = _create_user(db_session, 'sqli_user11', 'sqli11@example.com')
        headers = _auth_headers(app, user)

        payload = "1 OR 1=1"
        response = client.get(f'/api/tasks?project_id={payload}', headers=headers)
        # Should not return a 500 — either 200 (no rows) or 400 (type error) is acceptable
        assert response.status_code in (200, 400)

    def test_sqli_project_id_single_quote_does_not_error(self, client, app, db_session):
        """A single-quote in 'project_id' must not trigger a DB error."""
        user = _create_user(db_session, 'sqli_user12', 'sqli12@example.com')
        headers = _auth_headers(app, user)

        response = client.get("/api/tasks?project_id='", headers=headers)
        assert response.status_code in (200, 400)

    def test_sqli_project_id_union_payload_does_not_return_extra_rows(self, client, app, db_session):
        """
        A UNION SELECT payload in 'project_id' must not inject additional rows.
        """
        user = _create_user(db_session, 'sqli_user13', 'sqli13@example.com')
        project = _create_project(db_session, 'SQLi Project 13', user.id)
        _create_task(db_session, 'Real Task 13', 'real desc', project.id, user.id)
        headers = _auth_headers(app, user)

        payload = "1 UNION SELECT 1,2,3,4,5,6,7,8,9,10 --"
        response = client.get(f'/api/tasks?project_id={payload}', headers=headers)
        # Must not crash and must not return extra injected rows
        assert response.status_code in (200, 400)
        if response.status_code == 200:
            data = response.get_json()
            # All returned tasks must be real Task model instances (have valid int IDs)
            for task in data['tasks']:
                assert isinstance(task['id'], int)
