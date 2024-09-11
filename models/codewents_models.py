from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine, Column, String, ForeignKey, Boolean, DateTime, DECIMAL, Float
from sqlalchemy.dialects.postgresql import UUID, TIMESTAMP, TEXT
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
import uuid
from datetime import datetime

db= SQLAlchemy()

class Client(db.Model):
    __tablename__ = 'clients'
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    client_id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    client_name = db.Column(db.String(255), nullable=False)
    client_key = db.Column(db.String(255), nullable=False, unique=True)
    client_secret = db.Column(db.String(255), nullable=False, unique=True)
    created_at = db.Column(TIMESTAMP, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(TIMESTAMP, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

class AuthToken(db.Model):
    __tablename__ = 'auth_tokens'
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    token_id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    client_id = db.Column(UUID(as_uuid=True))
    access_token = db.Column(db.String(4096), unique=True, nullable=False)
    revoked = db.Column(Boolean, default=False)
    created_at = db.Column(TIMESTAMP, nullable=False, default=datetime.utcnow)
    expires_at = db.Column(TIMESTAMP, nullable=False)

class RefreshToken(db.Model):
    __tablename__ = 'refresh_tokens'
    id = db.Column(db.Integer, autoincrement=True, primary_key=True)
    client_id = db.Column(UUID(as_uuid=True))
    refresh_token = db.Column(db.String(4096), unique=True, nullable=False)
    created_at = db.Column(TIMESTAMP, nullable=False, default=datetime.utcnow)
    expires_at = db.Column(TIMESTAMP, nullable=False)

class OTP(db.Model):
    __tablename__ = 'otps'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    mobile_number = db.Column(db.String(20), nullable=False)
    otp = db.Column(db.String(6), nullable=False)
    created_at = db.Column(TIMESTAMP, nullable=False, default=datetime.utcnow)
    expires_at = db.Column(TIMESTAMP, nullable=False)