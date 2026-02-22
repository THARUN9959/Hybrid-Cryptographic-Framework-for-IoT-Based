FROM python:3.10-slim
WORKDIR /app
COPY camera.py .
RUN pip install cryptography
CMD ["python","-u","camera.py"]
