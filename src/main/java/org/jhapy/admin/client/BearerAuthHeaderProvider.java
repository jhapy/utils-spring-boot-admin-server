package org.jhapy.admin.client;

import de.codecentric.boot.admin.server.domain.entities.Instance;
import de.codecentric.boot.admin.server.web.client.HttpHeadersProvider;
import org.jhapy.commons.utils.HasLogger;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;

/**
 * @author Alexandre Clavaud.
 * @version 1.0
 * @since 18/10/2020
 */
public class BearerAuthHeaderProvider implements HttpHeadersProvider, HasLogger {

  private final OAuth2RestTemplate template;

  public BearerAuthHeaderProvider(OAuth2RestTemplate template) {
    this.template = template;
  }

  public HttpHeaders getHeaders(Instance ignored) {
    var loggerPrefix = getLoggerPrefix("getHeaders", ignored);

    logger()
        .debug(loggerPrefix + "Generate Token of type " + template.getAccessToken().getTokenType());

    HttpHeaders headers = new HttpHeaders();
    headers.set("Authorization",
        template.getAccessToken().getTokenType() + " " + template.getAccessToken().getValue());
    return headers;
  }
}