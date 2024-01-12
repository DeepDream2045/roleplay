# Use Python 3.10 version
FROM python:3.10

WORKDIR /app

COPY ./backend/requirement.txt /app/

RUN pip install -r requirement.txt

COPY ./backend/roleplay_chatbot/ /app/

CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]