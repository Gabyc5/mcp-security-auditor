FROM python:3.11-slim

WORKDIR /app
COPY server.py .

# No dependencies beyond stdlib — the vulnerable server
# deliberately uses only built-in modules to keep it simple.

EXPOSE 8080

CMD ["python", "server.py"]
