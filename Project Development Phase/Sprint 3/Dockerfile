FROM python:3.10
WORKDIR /app
ADD . /app
COPY requirements.txt /app
RUN python3 -m pip install -r requirements.txt
RUN python3 -m pip install ibm_db
RUN python3 -m pip install requests
RUN python3 -m pip install flask
EXPOSE  5000
CMD ["python","app.py"]