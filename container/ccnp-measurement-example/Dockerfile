FROM python:3.12.1-alpine3.19

WORKDIR /run/ccnp

COPY sdk/python3/dist/cctrusted_base*.whl ./
COPY sdk/python3/dist/ccnp*.whl ./
COPY container/ccnp-measurement-example/ccnp_measurement.py ./

RUN apk update && apk add bash vim
RUN pip install ./cctrusted_base*.whl ./ccnp*.whl && rm -f *.whl

ENTRYPOINT ["tail", "-f", "/dev/null"]
