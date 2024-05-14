from datetime import timedelta
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import SQLModel, Field, create_engine, Session, select
from dailydo_todo_app import setting
from typing import Annotated
from contextlib import asynccontextmanager
from dailydo_todo_app.auth import EXPIRY_TIME, authenticate_user, create_access_token, current_user, validate_refresh_token, create_refresh_token
from dailydo_todo_app.db import get_session, create_tables
from dailydo_todo_app.models import Todo, Todo_Create, Todo_Edit, Token, User
from dailydo_todo_app.router import user


@asynccontextmanager
async def lifespan(app: FastAPI):
    print('Creating Tables')
    create_tables()
    print("Tables Created")
    yield


app: FastAPI = FastAPI(
    lifespan=lifespan, title="dailyDo Todo App", version='1.0.0')

app.include_router(router=user.user_router)

@app.get('/')
async def root():
    return {"message": "Welcome to dailyDo todo app"}


# login . username, password
@app.post('/token', response_model=Token)
async def login(form_data:Annotated[OAuth2PasswordRequestForm, Depends()],
                session:Annotated[Session, Depends(get_session)]):
    user = authenticate_user (form_data.username, form_data.password, session)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    expire_time = timedelta(minutes=EXPIRY_TIME)
    access_token = create_access_token({"sub":form_data.username}, expire_time)

    refresh_expire_time = timedelta(days=7)
    refresh_token = create_refresh_token({"sub":user.email}, refresh_expire_time)

    return Token(access_token=access_token, token_type="bearer", refresh_token=refresh_token)

@app.post("/token/refresh")
def refresh_token(old_refresh_token:str,
                  session:Annotated[Session, Depends(get_session)]):
    
    credential_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid token, Please login again",
        headers={"www-Authenticate":"Bearer"}
    )
    
    user = validate_refresh_token(old_refresh_token,
                                  session)
    if not user:
        raise credential_exception
    
    expire_time = timedelta(minutes=EXPIRY_TIME)
    access_token = create_access_token({"sub":user.username}, expire_time)

    refresh_expire_time = timedelta(days=7)
    refresh_token = create_refresh_token({"sub":user.email}, refresh_expire_time)

    return Token(access_token=access_token, token_type= "bearer", refresh_token=refresh_token)



@app.post('/todos/', response_model=Todo)
async def create_todo(current_user:Annotated[User, Depends(current_user)],
                      todo: Todo_Create, 
                      session: Annotated[Session, Depends(get_session)]):
    
    new_todo = Todo(content=todo.content, user_id=current_user.id)
    
    session.add(new_todo)
    session.commit()
    session.refresh(new_todo)
    return new_todo


@app.get('/todos/', response_model=list[Todo])
async def get_all(current_user:Annotated[User, Depends(current_user)],
                  session: Annotated[Session, Depends(get_session)]):
    
    
    todos = session.exec(select(Todo).where(Todo.user_id == current_user.id)).all()

    if todos:
        return todos
    else:
        raise HTTPException(status_code=404, detail="No Task found")


@app.get('/todos/{id}', response_model=Todo)
async def get_single_todo(id: int, 
                          current_user:Annotated[User, Depends(current_user)],
                          session: Annotated[Session, Depends(get_session)]):
    
    user_todos = session.exec(select(Todo).where(Todo.user_id == current_user.id)).all()
    matched_todo = next((todo for todo in user_todos if todo.id == id),None)

    if matched_todo:
        return matched_todo
    else:
        raise HTTPException(status_code=404, detail="No Task found")


@app.put('/todos/{id}')
async def edit_todo(id: int, 
                    todo: Todo_Edit,
                    current_user:Annotated[User, Depends(current_user)], 
                    session: Annotated[Session, Depends(get_session)]):
    
    user_todos = session.exec(select(Todo).where(Todo.user_id == current_user.id)).all()
    existing_todo = next((todo for todo in user_todos if todo.id == id),None)

    if existing_todo:
        existing_todo.content = todo.content
        existing_todo.is_completed = todo.is_completed
        session.add(existing_todo)
        session.commit()
        session.refresh(existing_todo)
        return existing_todo
    else:
        raise HTTPException(status_code=404, detail="No task found")


@app.delete('/todos/{id}')
async def delete_todo(id: int,
                      current_user:Annotated[User, Depends(current_user)],
                      session: Annotated[Session, Depends(get_session)]):
    
    user_todos = session.exec(select(Todo).where(Todo.user_id == current_user.id)).all()
    todo = next((todo for todo in user_todos if todo.id == id),None)
    
    if todo:
        session.delete(todo)
        session.commit()
        # session.refresh(todo)
        return {"message": "Task successfully deleted"}
    else:
        raise HTTPException(status_code=404, detail="No task found")
