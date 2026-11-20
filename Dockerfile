# Lab build (Blue-Oryx onboarding): build the jar inside Docker, so the image
# needs no prebuilt target/ in the build context.
FROM docker.io/eclipse-temurin:25-jdk-noble AS build
WORKDIR /src
ENV MAVEN_OPTS="-Xmx1g"
COPY .mvn/ .mvn/
COPY mvnw pom.xml ./
# Cache the dependencies in their own layer while pom.xml is unchanged. A
# plugin go-offline cannot resolve is fetched by package below instead.
RUN ./mvnw -B -ntp dependency:go-offline -Dmaven.test.skip=true || true
COPY config/ config/
COPY src/ src/
RUN ./mvnw -B -ntp package -Dmaven.test.skip=true

# We need JDK as some of the lessons needs to be able to compile Java code
FROM docker.io/eclipse-temurin:25-jdk-noble

LABEL name="WebGoat: A deliberately insecure Web Application"
LABEL maintainer="WebGoat team"

RUN \
  useradd -ms /bin/bash webgoat && \
  chgrp -R 0 /home/webgoat && \
  chmod -R g=u /home/webgoat

USER webgoat

COPY --from=build --chown=webgoat /src/target/webgoat-*.jar /home/webgoat/webgoat.jar

EXPOSE 8080
EXPOSE 9090

ENV TZ=Europe/Amsterdam

WORKDIR /home/webgoat
ENTRYPOINT [ "java", \
   "-Duser.home=/home/webgoat", \
   "-Dfile.encoding=UTF-8", \
   "--add-opens", "java.base/java.lang=ALL-UNNAMED", \
   "--add-opens", "java.base/java.util=ALL-UNNAMED", \
   "--add-opens", "java.base/java.lang.reflect=ALL-UNNAMED", \
   "--add-opens", "java.base/java.text=ALL-UNNAMED", \
   "--add-opens", "java.desktop/java.beans=ALL-UNNAMED", \
   "--add-opens", "java.desktop/java.awt.font=ALL-UNNAMED", \
   "--add-opens", "java.base/sun.nio.ch=ALL-UNNAMED", \
   "--add-opens", "java.base/java.io=ALL-UNNAMED", \
   "--add-opens", "java.base/java.util=ALL-UNNAMED", \
   "--add-opens", "java.base/sun.nio.ch=ALL-UNNAMED", \
   "--add-opens", "java.base/java.io=ALL-UNNAMED", \
   "-Drunning.in.docker=true", \
   "-jar", "webgoat.jar", "--server.address=0.0.0.0" ]

HEALTHCHECK --interval=5s --timeout=3s \
  CMD curl --fail http://localhost:8080/WebGoat/actuator/health || exit 1
