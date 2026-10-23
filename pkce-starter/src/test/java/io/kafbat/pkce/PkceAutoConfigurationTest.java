package io.kafbat.pkce;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.web.util.UriComponentsBuilder;

class PkceAutoConfigurationTest {

  private ClientRegistration confidentialClient() {
    return ClientRegistration.withRegistrationId("kafbat")
        .clientId("kafbat")
        .clientSecret("test-secret")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
        .scope("openid", "profile")
        .authorizationUri("https://identity.example.test/authorize")
        .tokenUri("https://identity.example.test/token")
        .jwkSetUri("https://identity.example.test/jwks")
        .build();
  }

  private ApplicationContextRunner context() {
    return new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(PkceAutoConfiguration.class))
        .withBean(InMemoryReactiveClientRegistrationRepository.class,
            () -> new InMemoryReactiveClientRegistrationRepository(confidentialClient()));
  }

  @Test
  void autoConfigurationEnablesS256ForExistingConfidentialRegistration() throws Exception {
    context().run(application -> {
      var repository = application.getBean(InMemoryReactiveClientRegistrationRepository.class);
      var client = repository.findByRegistrationId("kafbat").block();
      assertThat(client).isNotNull();
      assertThat(client.getClientSecret()).isEqualTo("test-secret");
      assertThat(client.getClientSettings().isRequireProofKey()).isTrue();

      var resolver = new DefaultServerOAuth2AuthorizationRequestResolver(repository);
      var request = resolver.resolve(MockServerWebExchange.from(
          MockServerHttpRequest.get("https://kafbat.example.test/oauth2/authorization/kafbat")
              .build())).block();
      assertThat(request).isNotNull();
      String verifier = request.getAttribute("code_verifier");
      assertThat(verifier).isNotBlank();
      String expected = Base64.getUrlEncoder().withoutPadding().encodeToString(
          MessageDigest.getInstance("SHA-256")
              .digest(verifier.getBytes(StandardCharsets.US_ASCII)));
      var params = UriComponentsBuilder.fromUriString(request.getAuthorizationRequestUri())
          .build().getQueryParams();
      assertThat(params.getFirst("code_challenge")).isEqualTo(expected);
      assertThat(params.getFirst("code_challenge_method")).isEqualTo("S256");
    });
  }

  @Test
  void propertyCanDisableStarter() {
    context().withPropertyValues("kafbat.pkce.enabled=false").run(application -> {
      var client = application.getBean(InMemoryReactiveClientRegistrationRepository.class)
          .findByRegistrationId("kafbat").block();
      assertThat(client).isNotNull();
      assertThat(client.getClientSettings().isRequireProofKey()).isFalse();
    });
  }
}
