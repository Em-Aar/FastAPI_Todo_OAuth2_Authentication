from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session
from dailydo_todo_app.auth import current_user, get_user_from_db, hash_password, oauth_scheme
from dailydo_todo_app.db import get_session
from dailydo_todo_app.models import Register_User, User



user_router = APIRouter(
    prefix="/user",
    tags=["user"],
    responses={404: {"description": "Not found"}}
)

@user_router.get("/")
async def read_user():
    return {"message": "Welcome to dailyDo todo app User Page"}

@user_router.post("/register")
async def regiser_user (new_user:Annotated[Register_User, Depends()],
                        session:Annotated[Session, Depends(get_session)]):
    
    db_user = get_user_from_db(session, new_user.username, new_user.email)
    if db_user:
        raise HTTPException(status_code=409, detail="User with these credentials already exists")
    user = User(username = new_user.username,
                email = new_user.email,
                password = hash_password(new_user.password))
    session.add(user)
    session.commit()
    session.refresh(user)
    return {"message": f""" User with {user.username} successfully registered """}


@user_router.get('/me')
async def user_profile (current_user:Annotated[User, Depends(current_user)]):

    return current_user