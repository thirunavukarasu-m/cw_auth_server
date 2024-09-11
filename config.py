import os
#import logging

class Config:
    SQLALCHEMY_DATABASE_URI = "postgresql+psycopg2://thiru:thiru@0.tcp.in.ngrok.io:10086/codewents"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = "your_jwt_secret_key"  # Change this to a secure key
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', 'kirusubramani2812@gmail.com')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', 'pttl jpsz ejyl pezf')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'kirusubramani2812@gmail.com')
    TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID', 'ACdb714103a157a9646eb8b643812b44b1')
    TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN', 'e25a5b49ede720e39677330914a34a12')
    TWILIO_PHONE_NUMBER = os.environ.get('TWILIO_PHONE_NUMBER', '+15005550006')



    @staticmethod
    def init_app(app):
        try:
            app.config.from_object(Config)
        except Exception as e:
            #logging.error(f"Error loading configuration: {str(e)}")
            raise

