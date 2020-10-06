FROM openjdk:11-jre

ADD target/sigval-service-1.0.2.jar /app.jar
ENTRYPOINT ["java","-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:8000","-Dorg.apache.xml.security.ignoreLineBreaks=true","-jar","/app.jar"]

EXPOSE 8080
EXPOSE 8443
EXPOSE 8009
EXPOSE 8008
