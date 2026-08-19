FROM python:3.12-slim

WORKDIR /app

COPY server.py /app/server.py
COPY README.md /app/README.md

ENV PORT=8080

CMD ["python", "/app/server.py"]
