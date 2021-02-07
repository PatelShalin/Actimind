from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.security import OAuth2PasswordRequestForm
from models.jwt_user import JWTUser
from utils.security import authenticate_user, create_token, check_token, get_hashed_password, check_token_user_missions
from starlette.status import HTTP_401_UNAUTHORIZED
from utils.db_functions import db_insert_user, db_select_missions, db_select_users_missions
from utils.db_object import db

app = FastAPI()

@app.on_event("startup")
async def connect_db():
    await db.connect()

@app.on_event("shutdown")
async def disconnect_db():
    await db.disconnect()

@app.post("/signup")
async def post_user(user: JWTUser):
    user.password = get_hashed_password(user.password)
    await db_insert_user(user)
    jwt_token = create_token(user)
    return {"token":jwt_token}

@app.post("/login")
async def get_token(form_data: OAuth2PasswordRequestForm = Depends()):
    jwt_user_dict = {"username":form_data.username, "password":form_data.password}
    jwt_user = JWTUser(**jwt_user_dict)
    user = await authenticate_user(jwt_user)

    if user is None:
        raise HTTPException(status_code=HTTP_401_UNAUTHORIZED)

    jwt_token = create_token(user)
    return {"token":jwt_token}

@app.get("/missions")
async def get_missions(Authorization:str = Header(...)):
    valid = await check_token(Authorization[7:])
    if valid:
        result = await db_select_missions()
        return {"request": result}
    raise HTTPException(status_code=HTTP_401_UNAUTHORIZED)

@app.get("/user/{username}/missions")
async def get_users_missions(username:str, Authorization:str = Header(...)):
    valid = await check_token_user_missions(username, Authorization[7:])
    if valid:
        result = await db_select_users_missions(username)
        return {"request": result}
    raise HTTPException(status_code=HTTP_401_UNAUTHORIZED)