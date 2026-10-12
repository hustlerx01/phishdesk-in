FROM python:3.12-slim
RUN useradd -m app
WORKDIR /app
COPY --chown=app . .
USER app
# mount mail to analyse at /mail:  docker run --rm -v $PWD/inbox:/mail:ro phishdesk-in /mail -o /tmp/out
ENTRYPOINT ["python", "-m", "phishdesk.cli"]
CMD ["data/samples"]
