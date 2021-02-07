from pydantic import BaseModel
import enum


class User(BaseModel):
    name: str
    password: str
    email: str