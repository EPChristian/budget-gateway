FROM eclipse-temurin:17-jre-alpine

RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

COPY target/*.jar app.jar

RUN chown -R appuser:appgroup /app

USER appuser

ENTRYPOINT ["java", "-jar", "app.jar"]
