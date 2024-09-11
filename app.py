from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from models.codewents_models import db
from config import Config
from auth_blueprint import auth_bp
import os
#import logging

# Enable detailed logging for SQLAlchemy
#logging.basicConfig()
#logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING)

#Initialize the Flask application
app = Flask(__name__)

#Load configuration from Config class
app.config.from_object(Config)

# app.py
app.config['APP_SECRET'] = 'test_secret'


# Initialize extensions
db.init_app(app)
#migrate = Migrate(app, db)

@app.route('/')
def home():
    """
    Define the home route.
    Return: 
        str: A welcome message for the home page.
    """
    return 'Welcome to the Auth Server!'

# Register blueprints
app.register_blueprint(auth_bp, url_prefix='/auth')
# Register blueprints, models or other extensions if needed
with app.app_context():
    db.create_all()  # Creates tables for all models
#return app

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    app.run(host='0.0.0.0', port=port, debug=True)

