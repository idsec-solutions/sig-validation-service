package se.idsec.sigval.sigvalservice.configuration;

import io.netty.channel.ChannelOption;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;
import reactor.netty.transport.ProxyProvider;

import javax.net.ssl.SSLException;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;

@Configuration
public class WebClientConfig {

  // Read property to determine if SSL verification should be disabled
  @Value("${sigval-service.ignore-tls-trust-verification}")
  private boolean ignoreSsl;

  @Value("${sigval-service.http.connect-timeout-millis}") int connectTimeoutMillis;
  @Value("${sigval-service.http.read-timeout-millis}") int readTimeoutMillis;

  @Bean(name = "webClientBean")
  public WebClient webClient(WebClient.Builder webClientBuilder, final HttpProxyProperties httpProxyProperties)
      throws Exception {
    HttpClient httpClient = createHttpClient(httpProxyProperties);
    return webClientBuilder
        .clientConnector(new ReactorClientHttpConnector(httpClient))
        .build();
  }

  private HttpClient createHttpClient(final HttpProxyProperties httpProxyProperties) {
    HttpClient httpClient = HttpClient.create()
        .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, connectTimeoutMillis)
        .responseTimeout(Duration.ofMillis(readTimeoutMillis));
    if (ignoreSsl) {
      httpClient = httpClient
          .secure(sslContextSpec -> {
            try {
              sslContextSpec.sslContext(
                  SslContextBuilder.forClient()
                      .trustManager(InsecureTrustManagerFactory.INSTANCE) // Disable trust validation
                      .build()
              );
            }
            catch (SSLException e) {
              throw new RuntimeException(e);
            }
          });
    }

    if (httpProxyProperties != null && httpProxyProperties.getHost() != null) {
      httpClient = httpClient.proxy(typeSpec -> typeSpec
          .type(ProxyProvider.Proxy.HTTP)
          .host(httpProxyProperties.getHost())
          .port(httpProxyProperties.getPort())
          .username(httpProxyProperties.getUserName())
          .password(password -> httpProxyProperties.getPassword())
      );
    }
    return httpClient;
  }

}
