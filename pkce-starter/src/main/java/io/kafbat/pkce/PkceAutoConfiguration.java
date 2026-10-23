package io.kafbat.pkce;

import java.util.ArrayList;
import java.util.List;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

/**
 * Enables PKCE on Kafbat's existing confidential authorization-code registrations
 * without replacing its SecurityWebFilterChain or authentication managers.
 */
@AutoConfiguration
@ConditionalOnClass(InMemoryReactiveClientRegistrationRepository.class)
@ConditionalOnProperty(prefix = "kafbat.pkce", name = "enabled",
    havingValue = "true", matchIfMissing = true)
public class PkceAutoConfiguration {

  @Bean
  static BeanPostProcessor pkceClientRegistrationPostProcessor() {
    return new BeanPostProcessor() {
      @Override
      public Object postProcessAfterInitialization(Object bean, String beanName) {
        if (!(bean instanceof InMemoryReactiveClientRegistrationRepository repository)) {
          return bean;
        }

        List<ClientRegistration> updated = new ArrayList<>();
        boolean changed = false;
        for (ClientRegistration registration : repository) {
          if (AuthorizationGrantType.AUTHORIZATION_CODE.equals(registration.getAuthorizationGrantType())
              && !registration.getClientSettings().isRequireProofKey()) {
            updated.add(ClientRegistration.withClientRegistration(registration)
                .clientSettings(ClientRegistration.ClientSettings.builder().requireProofKey(true).build())
                .build());
            changed = true;
          } else {
            updated.add(registration);
          }
        }
        return changed ? new InMemoryReactiveClientRegistrationRepository(updated) : bean;
      }
    };
  }
}
