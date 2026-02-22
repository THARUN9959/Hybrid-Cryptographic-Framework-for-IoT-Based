FROM python:3.10-slim
WORKDIR /app
COPY cloud.py .
RUN pip install cryptography
CMD ["python","-u","cloud.py"]
