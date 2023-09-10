FROM openjdk:11-jre

ADD target/sigval-service-1.2.0.jar /app.jar
ENTRYPOINT ["java","-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:8000","-jar","/app.jar"]

EXPOSE 8080
EXPOSE 8443
EXPOSE 8009
EXPOSE 8008
