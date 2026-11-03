FROM node:22-alpine
WORKDIR /app
COPY . .
RUN npm ci
EXPOSE 1337
# The development server, not the production one, is what this image runs.
CMD ["npm", "run", "develop"]
