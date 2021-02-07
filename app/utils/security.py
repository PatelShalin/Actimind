from passlib.context import CryptContext
from models.jwt_user import JWTUser
from datetime import datetime, timedelta
from utils.const import JWT_EXPIRATION_TIME_MINUTES, JWT_SECRET_KEY, JWT_ALGORITHM
import jwt
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
import time
from starlette.status import HTTP_401_UNAUTHORIZED
from .db_functions import db_check_jwt_user, db_check_jwt_username

oauth_schema = OAuth2PasswordBearer(tokenUrl="/token")
pwd_context = CryptContext(schemes=["bcrypt"])

def get_hashed_password(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        return False

# Authenticate username and password to give JWT token
async def authenticate_user(user: JWTUser):
    potential_users = await db_check_jwt_user(user)
    is_valid = False
    if(potential_users is None):
        return None
    for user1 in potential_users:
        is_valid = verify_password(user.password, user1["password"])

    if is_valid:
            user.role = "admin"
            return user
    return None


# Create access JWT token
def create_token(user: JWTUser):
    expiration = datetime.utcnow() + timedelta(minutes=JWT_EXPIRATION_TIME_MINUTES)
    jwt_payload = {"sub": user.username, "exp": expiration, "role": user.role}
    jwt_token = jwt.encode(jwt_payload, JWT_SECRET_KEY, JWT_ALGORITHM)
    return jwt_token


# Check whether JWT token is correct
async def check_token(token: str = Depends(oauth_schema)):
    try:
        jwt_payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=JWT_ALGORITHM)
        username = jwt_payload.get("sub")
        expiration = jwt_payload.get("exp")
        if time.time() < expiration:
            is_valid = await db_check_jwt_username(username)
            if is_valid:
                return True
    except Exception as e:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED)

    raise HTTPException(status_code=HTTP_401_UNAUTHORIZED)

async def check_token_user_missions(un, token: str = Depends(oauth_schema)):
    try:
        jwt_payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=JWT_ALGORITHM)
        username = jwt_payload.get("sub")
        expiration = jwt_payload.get("exp")
        if time.time() < expiration and username == un:
            is_valid = await db_check_jwt_username(username)
            if is_valid:
                return True
    except Exception as e:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED)

    raise HTTPException(status_code=HTTP_401_UNAUTHORIZED)