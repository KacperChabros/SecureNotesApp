FROM python:3.10

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

#RUN chown -R www-data:www-data /app/data
#RUN chmod -R 770 /app/data

EXPOSE 5000

CMD ["uwsgi", "--ini", "uwsgi.ini"]
