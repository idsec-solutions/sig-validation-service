package se.idsec.sigval.sigvalservice.configuration;

import org.apache.catalina.connector.Connector;
import org.apache.coyote.ajp.AbstractAjpProtocol;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.ErrorPage;
import org.springframework.boot.web.servlet.server.ConfigurableServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;

@Configuration
public class TomcatSettings {
    @Value("${tomcat.ajp.port}")
    int ajpPort;

    @Value("${tomcat.ajp.remoteauthentication:#{false}}")
    String remoteAuthentication;

    @Value("${tomcat.ajp.enabled}")
    boolean tomcatAjpEnabled;

    @Bean
    public ConfigurableServletWebServerFactory servletContainer() {

        TomcatServletWebServerFactory webServerFactory = new TomcatServletWebServerFactory();
        if (tomcatAjpEnabled) {
            Connector connector = new Connector("AJP/1.3");
            connector.setPort(ajpPort);
            connector.setSecure(false);
            connector.setAllowTrace(false);
            connector.setScheme("http");
            ((AbstractAjpProtocol) connector.getProtocolHandler()).setSecretRequired(false);
            webServerFactory.addAdditionalTomcatConnectors(connector);
        }
        webServerFactory.addErrorPages(
                new ErrorPage(HttpStatus.NOT_FOUND, "/404-redirect"),
                new ErrorPage(HttpStatus.BAD_REQUEST, "/400"),
                new ErrorPage(HttpStatus.INTERNAL_SERVER_ERROR, "/500")
        );

        return webServerFactory;
    }
}
