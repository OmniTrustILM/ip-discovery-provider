# Build stage
FROM maven:3.9.16-eclipse-temurin-21 AS build

COPY src /home/app/src
COPY pom.xml /home/app
COPY settings.xml /root/.m2/settings.xml
COPY docker /home/app/docker

# Tests run here on purpose. publish_docker.yaml and build.yml are independent workflows on the
# same main/tag push, so nothing else stops a failing build from being published: skipping tests
# here would let the publish job push and sign an image while the test workflow is still running
# or already red. This stage is the only thing gating that.
RUN mvn -f /home/app/pom.xml clean package

# Optimize stage
FROM eclipse-temurin:21-jdk-alpine AS optimize

COPY --from=build /home/app/target/*.jar /app/app.jar

WORKDIR /app

# List jar modules
RUN jar xf app.jar
RUN jdeps \
    --ignore-missing-deps \
    --print-module-deps \
    --multi-release 21 \
    --recursive \
    --class-path 'BOOT-INF/lib/*' \
    app.jar > modules.txt

# Create a custom Java runtime.
# - 'jdk.crypto.ec' provides the SunEC security provider. jdeps cannot see it, because it is
#   resolved through ServiceLoader rather than referenced in bytecode, and without it every
#   ECDHE handshake and ECDSA certificate fails -- which is most of what this connector scans.
# Extend through ADDITIONAL_MODULES rather than editing the jlink invocation.
ARG ADDITIONAL_MODULES=jdk.crypto.ec
RUN $JAVA_HOME/bin/jlink \
    --add-modules $(cat modules.txt),${ADDITIONAL_MODULES} \
    --strip-debug \
    --no-man-pages \
    --no-header-files \
    --compress=zip-6 \
    --output /javaruntime

# Package stage
FROM alpine:3.24

ENV JAVA_HOME=/opt/jre
ENV PATH="${JAVA_HOME}/bin:${PATH}"

COPY --from=optimize /javaruntime $JAVA_HOME

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
