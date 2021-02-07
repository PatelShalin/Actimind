FROM tiangolo/uvicorn-gunicorn-fastapi:python3.7

COPY requirements.txt /
RUN pip install "idna==2.7" && python -m pip install -r /requirements.txt

COPY ./app /app