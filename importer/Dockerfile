FROM debian:stretch-slim

WORKDIR /app
RUN apt update && apt install -y jq mongo-tools curl
COPY nvd-update.sh /app/nvd-update.sh


CMD ["/app/nvd-update.sh"]
