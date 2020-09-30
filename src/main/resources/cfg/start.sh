#!/bin/sh

. /luna-init.sh

exec java $JAVA_OPTS -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:8000 -Dorg.apache.xml.security.ignoreLineBreaks=true -jar /app.jar
