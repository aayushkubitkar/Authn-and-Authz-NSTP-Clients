FROM python:3
RUN mkdir /solution
COPY server.py /solution/
COPY nstp_v3_pb2.py /solution/
RUN pip3 install protobuf
RUN pip3 install pynacl
RUN pip3 install passlib
RUN pip3 install passlib[argon2]
RUN chmod +x /solution/server.py /solution/nstp_v3_pb2.py
WORKDIR /solution
ENTRYPOINT [ "python", "./server.py" ]