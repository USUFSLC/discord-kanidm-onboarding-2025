FROM docker.io/python:3.12-slim

COPY ./requirements.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt

WORKDIR /fslc_discord

COPY ./fslc_discord/ ./fslc_discord

EXPOSE 5001

CMD ["/usr/local/bin/python3", "-m", "gunicorn", "-w", "4", "-b", "0.0.0.0:5001", "-c", "/etc/gunicorn.conf.py", "fslc_discord.fslc_discord:create_app()"]
