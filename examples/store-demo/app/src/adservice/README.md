# Ad Service

The Ad service provides advertisement based on context keys. If no context keys are provided then it returns random ads.

## Building locally

The Ad service uses Gradle to compile/install/distribute. To build Ad Service, run:

```
gradle installDist
```

It will create executable script src/adservice/build/install/hipstershop/bin/AdService

### Upgrading gradle version

If you need to upgrade the version of Gradle, update the pinned Gradle builder image in the Dockerfile.

## Building docker image

From `src/adservice/`, run:

```
docker build ./
```
