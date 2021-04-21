package org.jhapy.admin.config;

import de.codecentric.boot.admin.server.config.AdminServerAutoConfiguration;
import de.codecentric.boot.admin.server.config.AdminServerProperties;
import org.jhapy.admin.client.BearerAuthHeaderProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails;

/**
 * @author Alexandre Clavaud.
 * @version 1.0
 * @since 18/10/2020
 */
@Configuration
public class AdminServerConfiguration extends AdminServerAutoConfiguration {

  public AdminServerConfiguration(AdminServerProperties adminServerProperties) {
    super(adminServerProperties);
  }

  @Bean
  @Order(0)
  @ConditionalOnMissingBean
  public BearerAuthHeaderProvider bearerAuthHeaderProvider(
      @Value("${security.oauth2.client.accessTokenUri}") String accessTokenUri,
      @Value("${spring.security.oauth2.client.registration.oidc.client-id}") String clientId,
      @Value("${spring.security.oauth2.client.registration.oidc.client-secret}") String clientSecret) {
    ClientCredentialsResourceDetails details = new ClientCredentialsResourceDetails();

    details.setClientId(clientId);
    details.setClientSecret(clientSecret);
    details.setAccessTokenUri(accessTokenUri);
    details.setGrantType("client_credentials");

    return new BearerAuthHeaderProvider(new OAuth2RestTemplate(details));
  }

}
