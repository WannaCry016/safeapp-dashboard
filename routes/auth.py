import string
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from database import get_db
from models import User
from pydantic import BaseModel
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
import jwt
import os
from dotenv import load_dotenv
from models import DeviceStatus, User
import random
# from Crypto.Cipher import AES
# from Crypto.Util.Padding import pad, unpad
# import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import os
from Crypto.Cipher import AES

# AES Encryption Key (Must be 16, 24, or 32 bytes long)
# AES_SECRET_KEY = os.getenv("AES_SECRET_KEY", "12345678901234567890123456789012").encode()  # 32-byte key
# IV = b'\x00' * 16  # 16-byte IV (must match frontend)

# AES_SECRET_KEY = b'12345678901234567890123456789012'  # Must match Flutter
# IV = b'1234567890123456'  # Must match Flutter

# Encrypt data
# def encrypt_data(data: str) -> str:
#     cipher = AES.new(AES_SECRET_KEY.encode(), AES.MODE_CBC, AES_SECRET_KEY.encode())
#     encrypted_bytes = cipher.encrypt(pad(data.encode(), AES.block_size))
#     return base64.b64encode(encrypted_bytes).decode()

# Decrypt data
# def decrypt_data(encrypted_data: str) -> str:
#     cipher = AES.new(AES_SECRET_KEY.encode(), AES.MODE_CBC, AES_SECRET_KEY.encode())
#     decrypted_bytes = unpad(cipher.decrypt(base64.b64decode(encrypted_data)), AES.block_size)
#     return decrypted_bytes.decode()

# def decrypt_data(encrypted_text: str) -> str:
#     """AES decrypts the given data"""
#     encrypted_bytes = base64.b64decode(encrypted_text)
    
#     cipher = Cipher(algorithms.AES(AES_SECRET_KEY), modes.CBC(IV))
#     decryptor = cipher.decryptor()
#     decrypted_data = decryptor.update(encrypted_bytes) + decryptor.finalize()
    
#     return decrypted_data.decode().strip()

# def decrypt_data(encrypted_text):
#     try:
#         cipher = AES.new(AES_SECRET_KEY, AES.MODE_CBC, IV)
#         decrypted = cipher.decrypt(base64.b64decode(encrypted_text))
#         return decrypted.rstrip(b"\0").decode('utf-8')  # Remove padding
#     except Exception as e:
#         print(f"Decryption failed: {e}")
#         return None

KEY = b'01234567890123456789012345678901'  # 32 bytes
IV = b'0123456789012345'  # 16 bytes

# Function to remove PKCS7 padding
def remove_pkcs7_padding(data):
    padding_length = data[-1]  # Last byte tells how much padding was added
    return data[:-padding_length]  # Remove padding

def decrypt_aes(encrypted_text):
    try:
        cipher = AES.new(KEY, AES.MODE_CBC, IV)
        decrypted = cipher.decrypt(base64.b64decode(encrypted_text))
        cleaned_data = remove_pkcs7_padding(decrypted).decode('utf-8')  # Decode after removing padding
        return cleaned_data
    except Exception as e:
        return str(e)  # Return error message for debugging
    # try:
    #     cipher = AES.new(KEY, AES.MODE_CBC, IV)
    #     decrypted = cipher.decrypt(base64.b64decode(encrypted_text))
    #     return decrypted.rstrip(b"\0").decode('utf-8')  # Remove padding
    # except Exception as e:
    #     return str(e)  # Return error message for debugging

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")
ALGORITHM = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
auth_router = APIRouter()

# OAuth2 authentication scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

# Hash password
def hash_password(password: str):
    return pwd_context.hash(password)

# Verify password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Create JWT token
def create_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

# Decode and verify JWT token
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("username")

        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

        user = db.query(User).filter(User.username == username).first()
        if user is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token invalid")


class UserRegister(BaseModel):
    username: str
    password: str
    role: str  # Ensure we pass role in request body
    deviceid: str

@auth_router.post("/register")
def register(user: UserRegister, db: Session = Depends(get_db)):

    try:
        decrypted_username = decrypt_aes(user.username)
        decrypted_password = decrypt_aes(user.password)
        decrypted_role = decrypt_aes(user.role)
        decrypted_deviceid = decrypt_aes(user.deviceid)

        print(f"Decrypted Username: {decrypted_username}")
        print(f"Decrypted Password: {decrypted_password}")
        print(f"Decrypted Role: {decrypted_role}")
        print(f"Decrypted Device ID: {decrypted_deviceid}")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid encrypted data")
    
    existing_user = db.query(User).filter(User.username == decrypted_username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_password = hash_password(decrypted_password)
    new_user = User(username=decrypted_username, password_hash=hashed_password, deviceid=decrypted_deviceid, role=decrypted_role)
    
    # existing_user = db.query(User).filter(User.username == user.username).first()
    # if existing_user:
    #     raise HTTPException(status_code=400, detail="Username already exists")

    # hashed_password = hash_password(user.password)
    # new_user = User(username=user.username, password_hash=hashed_password, deviceid=user.deviceid, role=user.role)
    db.add(new_user)
    db.commit()
    return {"message": "User registered successfully"}


class UserLogin(BaseModel):
    username: str
    password: str

@auth_router.post("/login")
def login(user: UserLogin, db: Session = Depends(get_db)):
    try:
        decrypted_username = decrypt_aes(user.username)
        decrypted_password = decrypt_aes(user.password)

        print(f"Decrypted Username login: {decrypted_username}")
        print(f"Decrypted Password login: {decrypted_password}")
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid encrypted data")
    



    db_user = db.query(User).filter(User.username == decrypted_username).first()
    if not db_user or not verify_password(decrypted_password, db_user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_token({"username": db_user.username, "role": db_user.role})
    
    
    # db_user = db.query(User).filter(User.username == user.username).first()
    # if not db_user or not verify_password(user.password, db_user.password_hash):
    #     raise HTTPException(status_code=401, detail="Invalid credentials")

    # token = create_token({"username": db_user.username, "role": db_user.role})
    return {
        "access_token": token,
        "token_type": "bearer",  # Add token type to match Flutter's expectation
        "role": db_user.role      # Send role for UI-based authorization
    }

# Get Current User (Get Me) Endpoint
@auth_router.get("/me")
def get_me(current_user: User = Depends(get_current_user)):
    return {
        "username": current_user.username,
        "role": current_user.role,
        "deviceid": current_user.deviceid
    }

def generate_pin(length=6):
    """Generate a secure random 6-digit PIN"""
    return ''.join(random.choices(string.digits, k=length))

@auth_router.post("/block-device/{device_id}")
def block_device(device_id: str, db: Session = Depends(get_db)):
    device_status = db.query(DeviceStatus).filter(DeviceStatus.device_id == device_id).first()
    
    if not device_status:
        return {"error": "Device not found"}
    
    # Generate a new PIN
    new_pin = generate_pin()

    # Update database
    device_status.is_blocked = True
    device_status.new_pin = new_pin  # Store new PIN in DB
    db.commit()
    db.refresh(device_status)

    return {"message": "Device blocked successfully", "new_pin": new_pin}
    
    # if device_status:
    #     device_status.is_blocked = True
    #     device_status.new_pin = new_pin
    # else:
    #     device_status = DeviceStatus(device_id=device_id, is_blocked=True, new_pin=new_pin)
    #     db.add(device_status)
    
    # db.commit()
    # return {"message": "Device blocked successfully", "new_pin": new_pin}

@auth_router.get("/device-status/{device_id}")
def get_device_status(device_id: str, db: Session = Depends(get_db)):
    device_status = db.query(DeviceStatus).filter(DeviceStatus.device_id == device_id).first()
    
    if device_status:
        return {"is_blocked": device_status.is_blocked, "new_pin": device_status.new_pin}
    
    return {"is_blocked": False, "new_pin": None}


@auth_router.post("/unblock-device/{device_id}")
def unblock_device(device_id: str, entered_pin: str, db: Session = Depends(get_db)):
    device_status = db.query(DeviceStatus).filter(DeviceStatus.device_id == device_id).first()
    
    if not device_status or not device_status.is_blocked:
        raise HTTPException(status_code=400, detail="Device is not blocked")
    
    if device_status.new_pin != entered_pin:
        raise HTTPException(status_code=403, detail="Invalid PIN")

    # Unblock the device
    device_status.is_blocked = False
    device_status.new_pin = None
    db.commit()

    return {"message": "Device unblocked successfully"}

