from app import app, init_db

# Ensure schema/default data exists when started via WSGI server.
init_db()
