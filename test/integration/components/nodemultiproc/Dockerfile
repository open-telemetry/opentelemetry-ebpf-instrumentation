FROM node:20-slim

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY service.js .
COPY start-all.js .

EXPOSE 5000 5001 5002 5003

CMD [ "node", "start-all.js" ]

