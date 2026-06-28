FROM node:20-alpine

WORKDIR /app

# Copy package dependencies and install
COPY package*.json ./
RUN npm install

# Copy frontend source files
COPY . .

# Expose Vite dev server port
EXPOSE 5173

# Start Vite binding to 0.0.0.0 for container access
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
