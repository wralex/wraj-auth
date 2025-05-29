FROM node:slim AS build
WORKDIR /usr/src/app
COPY ["package.json", "package-lock.json*", "tsconfig.json*", "./"]
RUN npm install --silent && mv node_modules ../
COPY . .
RUN npm run build

FROM node:slim AS final
ENV NODE_ENV=production
WORKDIR /usr/src/app
COPY --from=build ["/usr/src/app/package.json", "/usr/src/app/package-lock.json*", "./"]
COPY --from=build ["/usr/src/app/dist", "./dist"]
COPY --from=build ["/usr/src/app/public", "./public"]
COPY --from=build ["/usr/src/app/views", "./views"]
RUN npm install --production --silent && mv node_modules ../
COPY . .
EXPOSE 3080
RUN chown -R node /usr/src/app
USER node
CMD ["npm", "start"]
