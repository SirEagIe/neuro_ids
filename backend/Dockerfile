FROM python

WORKDIR /app
COPY . .
RUN pip install -r requirements.txt

CMD ["celery", "-A", "main", "worker", "--loglevel=INFO"]
#CMD ["python", "-u", "./app.py"]
