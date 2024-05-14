FROM python:3.12-slim

WORKDIR /backend

COPY . /backend/

RUN pip install poetry

RUN poetry install

CMD ["poetry", "run", "uvicorn", "dailydo_todo_app.main:app", "--host", "0.0.0.0", "--port", "8000"]