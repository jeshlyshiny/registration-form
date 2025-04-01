from pydantic import BaseModel

class UserCreate(BaseModel):
    username: str
    email: str
    password: str  # This will be hashed before saving
