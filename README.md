# Sysnormal Sso client protector

![Version](https://img.shields.io/badge/maven--central-0.0.1--SNAPSHOT-orange)
![Java](https://img.shields.io/badge/Java-21-blue)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-4.x+-brightgreen)
![Spring Web](https://img.shields.io/badge/Spring-Web-orange)
![Jakarta](https://img.shields.io/badge/Jakarta-EE-orange)
![JPA](https://img.shields.io/badge/JPA-API-blue)
![Hibernate](https://img.shields.io/badge/Hibernate-ORM-59666C)
![Lombok](https://img.shields.io/badge/Lombok-annotations-pink)
![Jackson](https://img.shields.io/badge/Jackson-JSON-blue)
![Reflections](https://img.shields.io/badge/Reflections-runtime--scanning-lightgrey)
![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)

This starter provides a Spring Security auto-configuration for integrating Single Sign-On (SSO) authentication into your Spring Boot application. It includes a base security configuration and a filter to validate JWT tokens against an SSO server, ensuring secure access to protected endpoints.

This starter can also be used as a client implementation of the [SSO Starter](https://github.com/sysnormal1/sysnormal-spring-boot-sso-starter), allowing other Java-based APIs or backends to easily integrate into the same authentication ecosystem.

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
    <groupId>io.github.sysnormal1.security.auth.sso.starter</groupId>
    <artifactId>sysnormal-spring-boot-starter-sso-client-protector</artifactId>
    <version>0.0.1</version>
</dependency>
```

### Gradle
```groovy
implementation 'com.sysnormal.security.auth.sso.starter:sysnormal-spring-boot-starter-sso-client-protector:0.0.1-SNAPSHOT'
```

## Configuration and usage

This class is auto-configuration.


### Required Configuration Properties

You need to configure the following properties in your `application.yml` or `application.properties` file:

#### obrigatory configurations application.yml
```yaml
spring:
  jwt:
    public-key-path: PATH/TO/YOUR/public.pem
```

#### optional configurations application.yml
```yaml
spring: 
    security:
      public-endpoints: /api/online,/api/test
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
git clone https://github.com/sysnormal1/sysnormal-spring-boot-starter-sso-client-protector.git
cd sysnormal-spring-boot-starter-sso-client-protector
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

**Organization**  
GitHub: [@sysnormal1](https://github.com/sysnormal1)

---
