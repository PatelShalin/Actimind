from pydantic import BaseModel
from typing import List

class JWTUser(BaseModel):
    username: str
    password: str
    email: str = ""
    role: str = None
    missions: List[str] = []