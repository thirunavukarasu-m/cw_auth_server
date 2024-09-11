#import logging
import bcrypt
import jwt
import uuid
from datetime import datetime, timedelta
from config import Config
import re
import string
import random
from flask_mail import Mail, Message
from models.codewents_models import Client,AuthToken
from werkzeug.security import generate_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import hashlib
from flask import current_app
from twilio.rest import Client as TwilioClient
from twilio.base.exceptions import TwilioException

APP_SECRET="test_secret"

def get_twilio_client():
    """Returns the Twilio client instance."""
    return TwilioClient(
        current_app.config['TWILIO_ACCOUNT_SID'],
        current_app.config['TWILIO_AUTH_TOKEN']
    )

def validate_client_credentials(client_key, client_secret):
    try:
        client = Client.query.filter_by(client_key=client_key, client_secret=client_secret).first()
        return client
    except Exception as e:
        #logging.error(f"Error validating client credentials: {e}")
        return False

def generate_token(client_id, app_secret=APP_SECRET):
    """Generates an access token and refresh token."""
    try:
        expiration = datetime.utcnow() + timedelta(hours=1)
        payload = {
            'client_id': str(client_id),
            'iat': datetime.utcnow(),
            'exp': expiration
        }
        token = jwt.encode(payload, app_secret, algorithm='HS256')
        return token, expiration
    except Exception as e:
        #logging.error(f"Error generating token: {str(e)}")
        raise

def validate_token(token):
    try:
        app_secret = current_app.config.get('APP_SECRET', APP_SECRET)
        if not app_secret:
            raise ValueError("APP_SECRET is not set in the configuration")
        
        # Decode token directly as string
        #print("test_validate_token_1", token)
        payload = jwt.decode(token, app_secret, algorithms=['HS256'])
        #print("test_validate_token_2", payload)
        client_id = payload.get('client_id')
        #print("test_validate_token_3", client_id)
        
        client = Client.query.filter_by(client_id=client_id).first()
        if not client:
            return None, "Invalid client"
        
        return client_id, payload

    except jwt.ExpiredSignatureError as e:
        print(f"ExpiredSignatureError: {str(e)}")
        return None, "Token has expired"
    except jwt.InvalidTokenError as e:
        print(f"InvalidTokenError: {str(e)}")
        return None, "Invalid token"
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return None, "An unexpected error occurred"



def validate_email(email):
    """Validates the format of the email address."""
    try:
        return re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email) is not None
    except Exception as e:
        #logging.error(f"Error validating email: {str(e)}")
        raise

def generate_otp():
    """Generates a 6-digit OTP."""
    return str(random.randint(100000, 999999))

def send_otp(mobile_number, otp):
    """Sends an OTP to the given mobile number via Twilio."""
    try:
        client = get_twilio_client()
        message = client.messages.create(
            body=f"Your OTP code is {otp}",
            from_=current_app.config['TWILIO_PHONE_NUMBER'],
            to=mobile_number
        )
        #logging.info(f"OTP sent to {mobile_number}. Message SID: {message.sid}")
    except TwilioException as e:
        #logging.error(f"Error sending OTP: {str(e)}")
        raise