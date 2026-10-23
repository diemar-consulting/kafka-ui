# PKCE without rebuilding Kafbat UI (external Spring Boot starter)

This directory documents the **standalone starter** implementation on branch
[`pkce-bean`](https://github.com/diemar-consulting/kafka-ui/tree/pkce-bean).
The source-code alternative is documented on
[`issue/1721`](https://github.com/diemar-consulting/kafka-ui/tree/issue/1721/docs/pkce).

## Goal and design

Enable S256 PKCE for Kafbat's reactive OAuth2 **authorization-code** logins,
including confidential clients with a client secret, while keeping the Kafbat
application JAR byte-for-byte unchanged.

`pkce-starter/` is a separate Gradle Java library that packages Spring Boot
auto-configuration. Its `META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`
registers `PkceAutoConfiguration` automatically when loaded by Spring Boot.

The auto-configuration applies a `BeanPostProcessor` to Kafbat's
`InMemoryReactiveClientRegistrationRepository` and replaces it with
registrations copied with `ClientSettings.requireProofKey(true)`. Spring
Security's existing reactive OAuth2 authorization resolver then generates an
S256 challenge and retains the corresponding verifier for the token request.
The security filter chain, authentication managers, user services, RBAC logic,
client secret, and application sources are not replaced.

Only in-memory reactive client-registration repositories are targeted.
This is **not** a universal patch for arbitrary custom repository types.

## What changed on this branch

- `settings.gradle`: includes the separate `pkce-starter` Gradle module.
- `pkce-starter/build.gradle`: standalone Java library dependencies and tests.
- `pkce-starter/src/main/java/io/kafbat/pkce/PkceAutoConfiguration.java`:
  conditionally enables PKCE using a bean post-processor.
- `pkce-starter/src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`:
  registers auto-configuration.
- `pkce-starter/src/test/java/io/kafbat/pkce/PkceAutoConfigurationTest.java`:
  verifies S256 and the `kafbat.pkce.enabled=false` opt-out.
- `pkce-starter/verification/runtime_login.py`:
  starts an **unchanged** Kafbat executable JAR with the external starter
  and exercises authorization, token exchange, userinfo, and login-session
  behavior against a mock identity provider.
- `.github/workflows/pkce-bean-check.yml`: runs the starter build,
  builds Kafbat's original executable JAR, and runs the runtime smoke test.

## Build and run

Build the independent starter:

```bash
./gradlew :pkce-starter:check :pkce-starter:jar
```

Place the resulting `pkce-starter-*.jar` in an extension directory in the
container. **Copying the JAR alone does not make Spring Boot load it.**
Use a Spring Boot `PropertiesLauncher`-based command that adds the extension
directory to the loader path. For example, with the unchanged Kafbat
application JAR mounted at `/api.jar`:

```bash
java --add-opens java.rmi/javax.rmi.ssl=ALL-UNNAMED \
  -Dloader.path=/opt/kafbat/extensions \
  -cp /api.jar \
  org.springframework.boot.loader.launch.PropertiesLauncher
```

Adapt paths and retain existing JVM flags, arguments, environment variables,
and mounted configuration from the production image. Confirm your particular
Kafbat executable JAR contains the `PropertiesLauncher` class before
deploying. The entrypoint changes; **the Kafbat application JAR does not**.

The extension defaults to enabled when loaded. Set
`KAFBAT_PKCE_ENABLED=false` (property `kafbat.pkce.enabled=false`)
to disable the starter's behavior.

The detailed module-level instructions are in
[`pkce-starter/README.md`](../../pkce-starter/README.md).

## Verification

Run the same validation performed by CI:

```bash
./gradlew :pkce-starter:check :pkce-starter:jar :api:bootJar
python3 pkce-starter/verification/runtime_login.py
```

[GitHub Actions runtime verification — successful run](https://github.com/diemar-consulting/kafka-ui/actions/runs/39947552647)
passed on commit `0ea4449`. The runtime test verifies that an unchanged
Kafbat executable JAR loads the extension and that a mock provider sees a
matching S256 `code_challenge` and `code_verifier`, provides an access token
and userinfo, and completes login with a session.

This validates the technique against the **branch-built** original Kafbat
application JAR and a mock provider. The production image's exact executable
JAR, Java launch flags, Kubernetes/container configuration, and actual identity
provider still require environment-specific verification.

## Which implementation?

Use **this branch** for a separately distributed JAR that can be added to an
existing Kafbat image without recompiling the application.

Use [`issue/1721`](https://github.com/diemar-consulting/kafka-ui/tree/issue/1721/docs/pkce)
when you prefer PKCE wired explicitly into Kafbat's source-controlled
`OAuthSecurityConfig`.
