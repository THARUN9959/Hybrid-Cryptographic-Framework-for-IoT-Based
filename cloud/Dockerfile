FROM python:3.10-slim
WORKDIR /app
COPY cloud.py .
COPY llm_module.py .
RUN pip install cryptography requests
CMD ["python","-u","cloud.py"]
