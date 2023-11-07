FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt /app/

RUN pip install -r requirements.txt

COPY user-auth.py /app/

EXPOSE 5000

ENV FLASK_ENV=production

CMD ["python3", "user-auth.py"]
