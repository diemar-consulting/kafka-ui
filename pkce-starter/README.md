# Kafbat PKCE starter (external JAR)

This standalone JAR makes Spring Security's existing reactive OAuth2 authorization
resolver use **S256 PKCE for confidential authorization-code clients** without
replacing Kafbat's existing security filter chain, authentication manager, or RBAC.

It is a Spring Boot 3.5 / Spring Security 6.5 auto-configuration module, not a
fork of the application. It replaces the initialized
`InMemoryReactiveClientRegistrationRepository` bean with a same-type repository
whose authorization-code registrations have `requireProofKey(true)`. Other
registration properties are copied unchanged; other grant types are unchanged.

Build the external JAR:

```sh
./gradlew :pkce-starter:check :pkce-starter:jar
```

Disable it using `KAFBAT_PKCE_ENABLED=false` (property `kafbat.pkce.enabled`).

## Run with the original Kafbat application JAR unchanged

**Copying the starter JAR to the container is not sufficient**: Spring Boot's
standard executable-jar launcher does not scan arbitrary `/opt/lib` directories.
Use Spring Boot's `PropertiesLauncher`, and explicitly load the extension:

```sh
java -Dloader.path=/opt/kafbat/extensions \
  -cp /opt/kafbat/kafbat-ui.jar \
  org.springframework.boot.loader.launch.PropertiesLauncher
```

Place the starter JAR in `/opt/kafbat/extensions` in the image and adapt the
application JAR path as appropriate. This changes the container command, **not**
the Kafbat application binary. Verify the original executable JAR contains
Spring Boot's `PropertiesLauncher`, and test startup with the specific release
before deployment.

This starter uses Spring Security's default
`DefaultServerOAuth2AuthorizationRequestResolver`; it does not require two
additional OAuth2 beans. An independently declared resolver bean alone would
not be wired into Kafbat's explicit OAuth login chain.

**Scope:** This starter is designed for Kafbat's in-memory reactive registration
repository. It does not mutate external or custom repository implementations.
