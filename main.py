from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, Depends  # Ensure this line is present at the top
from database import Base, engine
from routes.auth import auth_router

import firebase_admin
from firebase_admin import messaging, credentials
from pydantic import BaseModel

from schemas.device import DeviceCreate, DeviceOut
from crud.device import upsert_device
from database import get_db
from sqlalchemy.orm import Session



app = FastAPI()  # Initialize FastAPI

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins (change this in production)
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods (GET, POST, etc.)
    allow_headers=["*"],  # Allow all headers
)

Base.metadata.create_all(engine)

# Register Routes
app.include_router(auth_router, prefix="/auth")

# Setup Firebase Admin
cred = credentials.Certificate("safeapp-51084-firebase-adminsdk-fbsvc-4676435ebd.json")
firebase_admin.initialize_app(cred)

@app.get("/")
def read_root():
    return {"message": "SafeApp Backend Running!"}



registered_tokens = set()

class DeviceToken(BaseModel):
    fcm_token: str

@app.post("/register-device")
# def register_device(data: DeviceToken):
#     registered_tokens.add(data.fcm_token)
#     return {"message": "Token registered"}
def update_device(device: DeviceCreate, db: Session = Depends(get_db)):
    return upsert_device(db, device)

@app.post("/wipe-device")
def wipe_device(data: DeviceToken):
    message = messaging.Message(
        data={"command": "wipe"},
        token=data.fcm_token,
    )
    response = messaging.send(message)
    return {"message": "Wipe command sent", "firebase_response": response}
