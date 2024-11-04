FROM openjdk:17-jdk-slim
COPY target/fapi-test-suite.jar /app/
EXPOSE 9090
ENTRYPOINT java -jar /app/fapi-test-suite.jar
