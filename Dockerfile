FROM python:3

WORKDIR /usr/src/app

COPY nmb.py /usr/src/app/

# docker run --rm -it -v /path/to/fileshare/:/usr/src/app/evidence -v /path/to/file.csv:/usr/src/app/file.csv corehelper:latest python nmb.py file.csv