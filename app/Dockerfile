FROM python:3.10

WORKDIR /app

COPY . /app

RUN python -m venv /opt/venv
RUN /opt/venv/bin/pip install --upgrade pip
RUN /opt/venv/bin/pip install --no-cache-dir -r requirements.txt
ENV PATH="/opt/venv/bin:$PATH"

CMD ["uwsgi", "--ini", "uwsgi.ini"]
