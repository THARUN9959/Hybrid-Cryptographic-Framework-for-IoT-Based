FROM python:3.10-slim
WORKDIR /app
COPY gateway.py .
RUN pip install cryptography
CMD ["python","-u","gateway.py"]
