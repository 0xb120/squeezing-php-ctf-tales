FROM node:20.19-alpine

RUN mkdir -p /sessions && chmod 0777 /sessions
COPY defender.js /app/defender.js

ENV SCAN_DIR=/sessions SCAN_INTERVAL_MS=400 SCAN_PORT=8080
EXPOSE 8080
CMD ["node", "/app/defender.js"]
