# Sysnormal Sso client protector

This starter provides a Spring Security auto-configuration for integrating Single Sign-On (SSO) authentication into your Spring Boot application. It includes a base security configuration and a filter to validate JWT tokens against an SSO server, ensuring secure access to protected endpoints.

This starter can also be used as a client implementation of the [SSO Starter](https://github.com/sysnormal1/java-spring-sso-starter), allowing other Java-based APIs or backends to easily integrate into the same authentication ecosystem.

## Features
- Configures Spring Security with a custom SSO authentication filter.
- Supports public endpoints that bypass authentication.
- Validates JWT tokens via an external SSO server.
- Configurable CORS settings for cross-origin requests.
- Disables CSRF protection for stateless API usage.

## Prerequisites
- Spring Boot 4+
- Java 21+
- An SSO server providing token validation endpoints
- Maven or Gradle for dependency management

## Installation

Add the following dependency to your `pom.xml` (Maven) or `build.gradle` (Gradle):

### Maven
```xml
<dependency>
    <groupId>com.sysnormal.starters.security.sso.spring</groupId>
    <artifactId>client-protector</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</dependency>
```

### Gradle
```groovy
implementation 'com.sysnormal.starters.security.sso.spring:client-protector:0.0.1-SNAPSHOT'
```

## Configuration and usage

This class is auto-configuration.


### Required Configuration Properties

You need to configure the following properties in your `application.yml` or `application.properties` file:

#### application.yml
```yaml
sso:
  base-endpoint: http://localhost:3000
  login-endpoint: /auth/login
  check-token-endpoint: /auth/check_token
  default-email: my_default_sso_user_email@mail.com
  default-password: my_default_sso_password
```



## 👥 Integration with SSO Starter

This client library is designed to integrate directly with the SSO Starter server, allowing seamless validation of authentication tokens and centralized access management across multiple applications.

For more details on the SSO server setup, refer to the main [SSO Starter](https://github.com/sysnormal1/java-spring-sso-starter).

---
## Contributing
For issues, feature requests, or contributions, please contact the starter maintainers or submit a pull request to the repository.

---


## 🧬 Clone the repository

To get started locally:

```bash
git clone https://github.com/sysnormal1/java-spring-sso-client-protector.git
cd java-spring-sso-client-protector
mvn install
```

## 🔧 Build and Local Test

```bash
mvn clean install
```

---

## ⚖️ License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Alencar Velozo**  
GitHub: [@aalencarvz1](https://github.com/aalencarvz1)

---

> 🔗 Published on [Maven Central (Sonatype)](https://central.sonatype.com/artifact/com.sysnormal.starters.security.sso.spring/client-protector)