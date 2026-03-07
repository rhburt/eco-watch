FROM node:20-alpine
WORKDIR /app
COPY package.json .
RUN npm install --production
COPY src/ ./src/
EXPOSE 3000
EXPOSE 9229
CMD ["node", "--inspect=0.0.0.0:9229", "src/server.js"]
