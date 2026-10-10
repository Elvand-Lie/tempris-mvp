# demo/api/Dockerfile — build with the repo demo/ directory as the context:
#   docker build -f api/Dockerfile -t terra-demo-api:<pack-sha-prefix> .
# (docker compose build/up in demo/ does exactly this.)
FROM python:3.12-slim
WORKDIR /srv
COPY api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY api/app ./app
COPY api/issue_invite.py ./issue_invite.py
COPY pack ./pack
COPY scripts ./scripts
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
