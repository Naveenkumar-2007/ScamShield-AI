"""Production WSGI entry point.

This avoids the name collision between the top-level app.py file and the
app/ package when Gunicorn imports the Flask application on Render.
"""
from app import create_app

app = create_app()
