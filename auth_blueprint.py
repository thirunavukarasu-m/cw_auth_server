from flask import Blueprint, request, jsonify, current_app, make_response
from sqlalchemy.exc import IntegrityError
from models.codewents_models import db, AuthToken, Client, OTP
#from main_server.models.pharma_client_models import db, User, UserDetails, Address
from utils import validate_client_credentials,validate_token,generate_token,validate_email,generate_otp,send_otp
from config import Config
from datetime import datetime, timedelta
import jwt
from sqlalchemy import and_
import logging
import requests

# Set up logging
#logging.basicConfig(level=logging.INFO)

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/authorize', methods=['POST'])
def authorize():
    try:
        data = request.json
        client_key = data.get('client_key')
        client_secret = data.get('client_secret')

        if not client_key or not client_secret:
            return jsonify({'error': 'Key and secret are required'}), 400

        # Validate client credentials from the codewents database
        client = validate_client_credentials(client_key, client_secret)
    
        if not client:
            return jsonify({"message": "Invalid client credentials"}), 401
        
        # Find the user based on the client credentials, assuming client is tied to a user
        #user = User.query.filter_by(client_id=client.client_id).first()

        #if not user:
            #return jsonify({"message": "No user associated with this client"}), 404

        # Mark expired tokens as revoked
        expired_tokens = AuthToken.query.filter(
            AuthToken.client_id == client.client_id,
            AuthToken.expires_at < datetime.utcnow(),
            AuthToken.revoked == False
        ).all()
        for token in expired_tokens:
            token.revoked = True
        db.session.commit()

        # Generate tokens
        token, expiration = generate_token(client.client_id)

        # Create and save AuthToken
        auth_token = AuthToken(
            #user_id=user.user_id,  # Adjust as needed
            client_id=client.client_id,
            access_token=token,
            expires_at=expiration,
            revoked=False
        )
        db.session.add(auth_token)
        db.session.commit()

        return jsonify({
            "access_token": token,
            "expires_at": expiration.isoformat()
        }), 200
    
    
    except ValueError as ve:
        #logging.error(f"ValueError in /authorize: {ve}")
        return jsonify({'error': 'Invalid input'}), 400
    except Exception as e:
        #logging.error(f"Exception in /authorize: {e}")
        return jsonify({'error': 'An error occurred while processing your request'}), 500


@auth_bp.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        access_token = request.headers.get('Authorization')

        if not access_token:
            return jsonify({'error': 'Access token is required'}), 401

        access_token = AuthToken.query.filter_by(access_token=access_token).first()

        if not access_token:
            return jsonify({'error': 'Invalid token'}), 401
        if access_token.expires_at < datetime.utcnow():
            return jsonify({'error': 'Access token has expired'}), 498

        #print("test_validate_token_0", access_token)
        client_id,payload = validate_token(access_token.access_token)
        #print("test_validate_token_5", client_id, payload)
        if not client_id:
            return jsonify({'error': 'Invalid client'}), 401


        if not data.get('username') or not data.get('email') or not data.get('password') or not data.get('confirm_password') or not data.get('mobile_number'):
            return jsonify({'error': 'Invalid data'}), 400

        if data['password'] != data['confirm_password']:
            return jsonify({'error': 'Passwords do not match'}), 400
        
        # Simulate sending the request to the main server (internal request)
        main_server_url = 'https://cw-main-server.onrender.com/main/register'  # Update with actual IP and port of main_server
        response = requests.post(main_server_url, json={
            'username': data['username'],
            'email': data['email'],
            'password': data['password'],
            'confirm_password': data['confirm_password'],
            'mobile_number': data['mobile_number'],
            'client_id': client_id
        })

        #Return the content, not the response object
        return make_response(response.content, response.status_code)

    except ValueError as ve:
        #logging.error(f"ValueError in /register: {ve}")
        return jsonify({'error': 'Invalid input'}), 400
    except Exception as e:
        #logging.error(f"Exception in /register: {e}")
        return jsonify({'error': 'An error occurred while processing your request'}), 500
   
@auth_bp.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        access_token = request.headers.get('Authorization')

        if not access_token:
            return jsonify({'error': 'Access token is required'}), 401

        access_token = AuthToken.query.filter_by(access_token=access_token).first()

        if not access_token:
            return jsonify({'error': 'Invalid token'}), 401
        if access_token.expires_at < datetime.utcnow():
            return jsonify({'error': 'Access token has expired'}), 498

        if not data.get('email'):
            #current_app.logger.warning("Email is missing")
            return jsonify({"error": "Email is required"}), 400
        if not data.get('password'):
            #current_app.logger.warning("Password is missing")
            return jsonify({"error": "Password is required"}), 400
        if not validate_email(data.get('email')):
            #current_app.logger.warning("Invalid email format")
            return jsonify({"error": "Invalid email format"}), 400

        # Internal request to main/login to verify user's credentials
        main_server_url = 'https://cw-main-server.onrender.com/main/login'  # Update with actual IP and port of main_server
        response = requests.post(main_server_url, json={
                'email': data['email'],
                'password': data['password']
            })

        #Return the content, not the response object
        return make_response(response.content, response.status_code)

    except ValueError as ve:
        #current_app.logger.warning(f"ValueError in /login: {ve}")
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        #current_app.logger.error(f"Exception in /login: {str(e)}")
        return jsonify({"error": "An error occurred during login"}), 500

@auth_bp.route('/forgot-password', methods=['POST'])
def forgot_password():
    try:
        access_token = request.headers.get('Authorization')
        data = request.json
        email = data.get('email')


        if not access_token:
            return jsonify({'error': 'Access token is required'}), 401

        access_token = AuthToken.query.filter_by(access_token=access_token).first()
        if not access_token:
            return jsonify({'error': 'Invalid token'}), 401
        if access_token.expires_at < datetime.utcnow():
            return jsonify({'error': 'Access token has expired'}), 498

        if not email:
            return jsonify({'error': 'Email is required'}), 400
        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400

        # Simulate sending the request to the main server (internal request)
        main_server_url = 'https://cw-main-server.onrender.com/forgot-password'  # Update with actual IP and port of main_server
        response = requests.post(main_server_url, json={'email': email})

        #Return the content, not the response object
        return make_response(response.content, response.status_code)

    except ValueError as ve:
        #logging.error(f"ValueError in /forgot-password: {ve}")
        return jsonify({'error': 'Invalid input'}), 400
    except Exception as e:
        #logging.error(f"Exception in /forgot-password: {e}")
        return jsonify({'error': 'An error occurred while processing your request'}), 500

@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    try:
        data = request.json
        reset_token = data.get('token')
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')
        access_token = request.headers.get('Authorization')

        if not access_token:
            return jsonify({'error': 'Access token is required'}), 401

        access_token = AuthToken.query.filter_by(access_token=access_token).first()
        if not access_token:
            return jsonify({'error': 'Invalid token'}), 401
        if access_token.expires_at < datetime.utcnow():
            return jsonify({'error': 'Access token has expired'}), 498

        if new_password != confirm_password:
            return jsonify({'error': 'Passwords do not match'}), 400

        # Simulate sending the request to the main server (internal request)
        main_server_url = 'https://cw-main-server.onrender.com/reset-password'  # Update with actual IP and port of main_server
        response = requests.post(main_server_url, json={
                'token': reset_token,
                'new_password': new_password,
                'confirm_password': confirm_password
            })

        #Return the content, not the response object
        return make_response(response.content, response.status_code)

    except ValueError as ve:
        #logging.error(f"ValueError in /reset-password: {ve}")
        return jsonify({'error': 'Invalid input'}), 400
    except Exception as e:
        #logging.error(f"Exception in /reset-password: {e}")
        return jsonify({'error': 'An error occurred while processing your request'}), 500

@auth_bp.route('/change-password-request', methods=['POST'])
def change_password_request():
    try:
        access_token = request.headers.get('Authorization')
        data = request.json
        email = data.get('email')

        if not access_token:
            return jsonify({'error': 'Access token is required'}), 401

        access_token_record = AuthToken.query.filter_by(access_token=access_token).first()
        if not access_token_record:
            return jsonify({'error': 'Invalid token'}), 401
        if access_token_record.expires_at < datetime.utcnow():
            return jsonify({'error': 'Access token has expired'}), 498

        if not email:
            return jsonify({'error': 'Email is required'}), 400
        if not validate_email(email):
            return jsonify({'error': 'Invalid email format'}), 400

        # Simulate sending the request to the main server (internal request)
        main_server_url = 'https://cw-main-server.onrender.com/change-password-request'  # Update with actual IP and port of main_server
        response = requests.post(main_server_url, json={'email': email})

        #Return the content, not the response object
        return make_response(response.content, response.status_code)

    except ValueError as ve:
        #logging.error(f"ValueError in /change-password-request: {ve}")
        return jsonify({'error': 'Invalid input'}), 400
    except Exception as e:
        #logging.error(f"Exception in /change-password-request: {e}")
        return jsonify({'error': 'An error occurred while processing your request'}), 500

@auth_bp.route('/change-password', methods=['POST'])
def change_password():
    try:
        data = request.json
        reset_token = data.get('token')
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')
        access_token = request.headers.get('Authorization')

        if not access_token:
            return jsonify({'error': 'Access token is required'}), 401

        access_token_record = AuthToken.query.filter_by(access_token=access_token).first()
        if not access_token_record:
            return jsonify({'error': 'Invalid token'}), 401
        if access_token_record.expires_at < datetime.utcnow():
            return jsonify({'error': 'Access token has expired'}), 498

        if new_password != confirm_password:
            return jsonify({'error': 'Passwords do not match'}), 400

        # Simulate sending the request to the main server (internal request)
        main_server_url = 'https://cw-main-server.onrender.com/change-password'  # Update with actual IP and port of main_server
        response = requests.post(main_server_url, json={
                'token': reset_token,
                'current_password': current_password,
                'new_password': new_password,
                'confirm_password': confirm_password
            })

        return make_response(response.content, response.status_code)

    except ValueError as ve:
        #logging.error(f"ValueError in /change-password: {ve}")
        return jsonify({'error': 'Invalid input'}), 400
    except Exception as e:
        #logging.error(f"Exception in /change-password: {e}")
        return jsonify({'error': 'An error occurred while processing your request'}), 500

@auth_bp.route('/request-otp', methods=['POST'])
def request_otp():
    try:
        data = request.get_json()
        mobile_number = data.get('mobile_number')

        if not mobile_number:
            return jsonify({'error': 'Mobile number is required'}), 400

        last_otp = OTP.query.filter_by(mobile_number=mobile_number).order_by(OTP.created_at.desc()).first()
        if last_otp and datetime.utcnow() - last_otp.created_at < timedelta(minutes=1):
            return jsonify({'error': 'Please wait 1 minute before requesting a new OTP'}), 429
            
        # Generate OTP
        otp = generate_otp()
        created_at = datetime.utcnow()
        expires_at = datetime.utcnow() + timedelta(minutes=5)  # OTP valid for 5 minutes

        # Store OTP in the database
        otp_record = OTP(mobile_number=mobile_number, otp=otp, created_at=created_at, expires_at=expires_at)
        db.session.add(otp_record)
        db.session.commit()

        # Send OTP to the mobile number
        send_otp(mobile_number, otp)

        # Return the mobile number and OTP in the response for testing purposes
        return jsonify({"mobile_number": mobile_number, "otp": otp, "message": "OTP sent to the provided mobile number"}), 200

    except Exception as e:
        #current_app.logger.error(f"Exception in /request-otp: {str(e)}")
        return jsonify({"error": "An error occurred while sending OTP"}), 500
        
@auth_bp.route('/register-with-mobile', methods=['POST'])
def register_with_mobile():
    try:
        data = request.get_json()
        mobile_number = data.get('mobile_number')
        otp = data.get('otp')

        if not mobile_number or not otp:
            return jsonify({'error': 'Mobile number and OTP are required'}), 400

        # Step 1: Verify OTP
        otp_record = OTP.query.filter_by(mobile_number=mobile_number, otp=otp).first()

        if not otp_record:
            return jsonify({'error': 'Invalid OTP'}), 400

        if otp_record.expires_at < datetime.utcnow():
            return jsonify({'error': 'OTP has expired'}), 400

        # Step 2: If OTP is valid, send an internal request to the main server to register the user
        main_server_url = 'https://cw-main-server.onrender.com/register-with-mobile'
        
        try:
            response = requests.post(main_server_url, json={
                'mobile_number': mobile_number
            })

            #current_app.logger.info(f"Request sent to {main_server_url}, response status code: {response.status_code}")
            #current_app.logger.debug(f"Response content: {response.content}")

            return make_response(response.content, response.status_code)
        
        except requests.exceptions.RequestException as e:
            #current_app.logger.error(f"Error making request to main server: {str(e)}")
            return jsonify({"error": "An error occurred while sending request to the main server"}), 500

    except Exception as e:
        #current_app.logger.error(f"Exception in /register-with-mobile: {str(e)}")
        return jsonify({"error": "An error occurred during registration"}), 500
