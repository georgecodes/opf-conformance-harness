FROM gradle:8.10-jdk17 AS builder
COPY --chown=gradle:gradle . /harness
WORKDIR /harness
RUN gradle clean fatjar -x test --no-daemon

FROM amazoncorretto:17-al2-jdk

ARG JAR_FILE=/harness/build/libs/harness-all.jar
COPY --from=builder ${JAR_FILE} harness.jar

EXPOSE 9090
ENTRYPOINT ["java","-jar","/harness.jar"]
