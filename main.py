from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from typing import Dict
from datetime import timedelta

from models import User, UserCreate
from auth import (
    get_password_hash,
    verify_password,
    create_access_token,
    get_current_user,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    create_password_reset_token,
    verify_password_reset_token,
)

app = FastAPI()

# Simple in-memory store as a dictionary for demonstration
fake_db: Dict[str, User] = {}


@app.post("/signup")
def signup(user_data: UserCreate):
    # Check if user already exists
    if user_data.username in fake_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already taken"
        )
    # Hash the password and store the user
    hashed_password = get_password_hash(user_data.password)
    new_user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hashed_password
    )
    fake_db[user_data.username] = new_user
    return {"message": "User created successfully"}


@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    # OAuth2PasswordRequestForm provides: form_data.username, form_data.password
    user = fake_db.get(form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    # Create JWT token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=access_token_expires
    )

    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/protected")
def protected_route(username: str = Depends(get_current_user)):
    return {"message": f"Welcome, {username}. You have access to this protected route!"}


@app.post("/forgot-password")
def forgot_password(forgot_data: ForgotPassword):
    # Find user with the given email
    user = next((u for u in fake_db.values() if u.email == forgot_data.email), None)
    if not user:
        # For security reasons, don't reveal if the email exists or not
        return {"message": "If the email exists, a password reset token will be sent"}
    
    # Generate password reset token
    reset_token = create_password_reset_token(forgot_data.email)
    
    # In a real application, send this token via email
    # For demo purposes, we'll return it directly
    return {
        "message": "Password reset token generated",
        "token": reset_token  # In production, this would be sent via email instead
    }

@app.post("/reset-password")
def reset_password(reset_data: ResetPassword):
    # Verify the reset token and get the email
    email = verify_password_reset_token(reset_data.token)
    
    # Find user with the email
    user = next((u for u in fake_db.values() if u.email == email), None)
    if not user:
        raise HTTPException(status_code=400, detail="User not found")
    
    # Update the password
    user.hashed_password = get_password_hash(reset_data.new_password)
    fake_db[user.username] = user
    
    return {"message": "Password has been reset successfully"}