FROM node:22-alpine
WORKDIR /app
COPY scripts/ scripts/
COPY package.json .
EXPOSE 8080
CMD ["node", "scripts/relay.mjs", "--port", "8080"]
