FROM python:3.9

ADD certs/ .
ADD main.py .
ADD requirements.txt .

RUN pip install -r requirements.txt

EXPOSE 8433

# Run Server
CMD ["python","-u", "main.py"]
