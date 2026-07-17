FROM node:22-alpine

# better-sqlite3 compiles native code; build tools needed in alpine
RUN apk add --no-cache python3 make g++

WORKDIR /app

# Install dependencies first (layer-cached unless package.json changes)
COPY package.json ./
RUN npm install --omit=dev

# Copy application source
COPY server.js ./
COPY public ./public

# /data is where the Fly.io persistent volume is mounted
# DB_DIR tells server.js to store attendance.db and .jwt_secret there
ENV DB_DIR=/data
ENV PORT=3456

EXPOSE 3456

CMD ["node", "--no-warnings", "server.js"]
