FROM node:22-alpine

WORKDIR /app

# pg is pure JS — no native build tools needed
COPY package.json ./
RUN npm install --omit=dev --omit=optional

COPY server.js ./
COPY public ./public

ENV PORT=3456

EXPOSE 3456

CMD ["node", "--no-warnings", "server.js"]
