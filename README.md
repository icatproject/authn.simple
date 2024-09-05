# authn_simple

[![Build Status](https://github.com/icatproject/authn.simple/workflows/CI%20Build/badge.svg?branch=master)](https://github.com/icatproject/authn.simple/actions?query=workflow%3A%22CI+Build%22)

This project uses Quarkus, a Java Framework. <https://quarkus.io/>

## Running the application in dev mode

You can run this application locally in dev mode that enables live coding using:

```shell script
./mvnw compile quarkus:dev
```
> **_NOTE:_**  Quarkus also ships with a Dev UI, which is available in dev mode only at <http://localhost:8080/q/dev/>.

## List of endpoints 

| Location        | Example                                                                                                                                          | Results                                                      |
| --------------- |--------------------------------------------------------------------------------------------------------------------------------------------------| ------------------------------------------------------------ |
| `/version`      | `curl http://localhost:8080/authn.simple/version`                                                                                                | `{"version":"4.0.0"}`                                        |
| `/description`  | `curl http://localhost:8080/authn.simple/description `                                                                                           | `{"keys":[{"name":"username"},{"name":"password","hide":true}]}` |
| `/authenticate` | `curl -d json='{"credentials":[{"username":"validUserName"},{"password":"validUserPassword"}]}' http://localhost:8080/authn.simple/authenticate` | `{"username":"dummy","mechanism":"simple"}`                  |

## Packaging and running the application

The application can be packaged using:

```shell script
./mvnw clean package -DskipTests
```

It produces the `.jar` file in the `target/` directory.
Be aware that it’s not an _über-jar_ as the dependencies are copied into the `target/quarkus-app/lib/` directory.

## Testing

The application uses integration tests to fully verify the api endpoints. The package needs to be built above first.

```shell script
./mvnw failsafe:integration-test
```

The application can be run using:

```shell script
java -jar target/quarkus-app/quarkus-run.jar
```

If you want to build an [_über-jar_](https://blog.payara.fish/what-is-a-java-uber-jar), execute the following command:

```shell script
./mvnw package -DskipTests -Dquarkus.package.jar.type=uber-jar
```

The application, packaged as an _über-jar_, is now runnable using `java -jar target/*-runner.jar`.

## Docker :whale:

Once these packages have been built, they can be copied into a container and run.

Various dockerfiles exist in the `src/main/docker` folder for this.

For example, to build a native docker image locally:

```shell script
# from the root folder
docker build -f src/main/docker/Dockerfile.native -t quarkus/qarkus_auth
```

Then the image can be run:

```shell script
docker run -i --rm -p 8080:8080 quarkus/qarkus_auth
```

Once the CI has built the image, it can be run by:

```shell script
docker run -p 8080:8080 harbor.stfc.ac.uk/icat/authn_simple:<git branch name>
```




