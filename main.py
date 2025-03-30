from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI  # Ensure this line is present at the top
from database import Base, engine
from routes.auth import auth_router

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

@app.get("/")
def read_root():
    return {"message": "SafeApp Backend Running!"}
