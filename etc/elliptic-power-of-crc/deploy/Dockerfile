# NO_DIGEST_PIN
FROM python:3

RUN apt-get update; \
    apt-get install -y socat

ENV user ctf
ENV port 1557
EXPOSE 1557

RUN adduser --disabled-password --gecos "" $user

WORKDIR /home/$user/
RUN pip install fastcrc
RUN pip install fastecdsa
COPY prob.py /home/$user/
COPY flag /home/$user/

CMD socat \
    TCP-LISTEN:$port,reuseaddr,fork \
    EXEC:"python prob.py"