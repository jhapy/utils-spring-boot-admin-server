package org.jhapy.admin.config;

import de.codecentric.boot.admin.server.config.AdminServerAutoConfiguration;
import de.codecentric.boot.admin.server.config.AdminServerProperties;
import java.util.Collections;
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
  public BearerAuthHeaderProvider bearerAuthHeaderProvider(@Value("${security.oauth2.client.accessTokenUri}") String accessTokenUri) {
    ClientCredentialsResourceDetails details = new ClientCredentialsResourceDetails();

    //set you details here: id, clientid, secret, tokenendpoint
    details.setClientId("utils-spring-boot-admin-server");
    details.setClientSecret("0aed9af3-0a6f-44fa-b32d-53f60fb08cf7");
    details.setAccessTokenUri(accessTokenUri);
    details.setGrantType("client_credentials");
    //details.setScope(Collections.singletonList("actuator"));

    return new BearerAuthHeaderProvider(new OAuth2RestTemplate(details));
  }

}
