# Gunicorn configuration for the ProjectHub backend.
# Production WSGI server with bounded concurrency and a single, race-free
# schema initialization.

bind = "0.0.0.0:5000"
workers = 4
threads = 2
timeout = 30

# Import app.py ONCE in the master process, before workers fork.
# app.py runs init_db()/db.create_all() + seeding at import time; without this,
# all workers ran create_all() concurrently against an empty DB and collided
# (psycopg2 UniqueViolation on pg_type -> "Worker failed to boot"). Preloading
# makes that initialization happen exactly once.
preload_app = True


def post_fork(server, worker):
    # The master opened DB connections during preload (create_all/seed).
    # Those sockets must not be shared across forked workers, so drop the
    # inherited pool and let each worker open its own fresh connections.
    from app import app, db
    with app.app_context():
        db.engine.dispose()
