FROM swipl:stable
WORKDIR /app
COPY . /app
CMD ["swipl", "/app/main.pl"]
