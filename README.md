# Spring Boot 3.0 Security with JWT Implementation
This project demonstrates the implementation of security using Spring Boot 3.0 and JSON Web Tokens ([JWT](https://jwt.io/)).

It includes the following features:
## Features
* User registration and login with JWT authentication
* Password encryption using BCrypt
* Role-based authorization with Spring Security
* Customized access denied handling

## Technologies
* Spring Boot 3.0
* Spring Security
* JSON Web Tokens (JWT)
* BCrypt
* Maven

## Getting Started
To get started with this project, you will need to have the following installed on your local machine:

* JDK 8+
* Maven 3+

To build and run the project, follow these steps:

* Clone the repository: `git clone https://github.com/senoramarillo/spring-boot-3-jwt-security.git`
* Navigate to the project directory: cd spring-boot-security-jwt
* Build the project: mvn clean install
* Run the project: mvn spring-boot:run
-> The application will be available at http://localhost:8080.

Examples:
GET localhost:8080/api/v1/demo-controller
Content-Type: application/json

###
POST {{baseUrl}}/api/v1/auth/register
Content-Type: application/json

```
{
"firstname": "Frank",
"lastname": "Miller",
"email": "frank.miller@gmail.com",
"password": "1234"
}
```

###
POST {{baseUrl}}/api/v1/auth/authenticate
Content-Type: application/json

```
{
"email": "frank.miller@gmail.com",
"password": "1234"
}
```

# License
This is based on [spring-boot-3-jwt-security](https://github.com/ali-bouali/spring-boot-3-jwt-security) by Ali B. Thanks go to him for the great base.
