# Build stage
FROM maven:3.9.16-eclipse-temurin-21 AS build
COPY src /home/app/src
COPY pom.xml /home/app
COPY settings.xml /root/.m2/settings.xml
COPY docker /home/app/docker
RUN mvn -f /home/app/pom.xml clean package

# Package stage
FROM eclipse-temurin:21.0.11_10-jre-alpine

LABEL org.opencontainers.image.authors="ILM <ilm@omnitrust.com>"

# apply outstanding Alpine security updates on top of the base image
RUN apk --no-cache upgrade

# add non root user ip-discovery-provider
RUN addgroup --system --gid 10001 ip-discovery-provider && adduser --system --home /opt/ip-discovery-provider --uid 10001 --ingroup ip-discovery-provider ip-discovery-provider

COPY --from=build /home/app/docker /
COPY --from=build /home/app/target/*.jar /opt/ip-discovery-provider/app.jar

WORKDIR /opt/ip-discovery-provider

ENV JDBC_URL=
ENV JDBC_USERNAME=
ENV JDBC_PASSWORD=
ENV DB_SCHEMA=network
ENV PORT=8080
ENV JAVA_OPTS=

USER 10001

ENTRYPOINT ["/opt/ip-discovery-provider/entry.sh"]
