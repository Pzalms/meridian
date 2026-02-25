FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y make

COPY . $SRC/meridian
WORKDIR $SRC/meridian
COPY .clusterfuzzlite/build.sh $SRC/build.sh
