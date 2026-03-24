FROM node:22-alpine
WORKDIR /app
COPY scripts/ scripts/
COPY package.json .
EXPOSE 8080
# Full node: relay + sensor collection
CMD ["node", "scripts/clawfeel.mjs", "--full-node", "--relay-port", "8080", "--interval", "30", "--count", "999999", "--no-daemon"]
