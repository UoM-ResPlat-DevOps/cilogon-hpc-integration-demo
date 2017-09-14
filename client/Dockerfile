FROM jbasney/globus
RUN yum -y update && yum -y install git wget python-setuptools \
    && yum clean all

# Install Let's Encrypt and it's CA certificates (but don't request certificate yet).
RUN git clone https://github.com/letsencrypt/letsencrypt
RUN git clone https://github.com/cilogon/letsencrypt-certificates.git
RUN cd letsencrypt-certificates/ && \
    make check && \
    make install

# Install CILogon CA certificates.
RUN wget https://cilogon.org/cilogon-ca-certificates.tar.gz
RUN tar -xvzf cilogon-ca-certificates.tar.gz
RUN cp cilogon-ca/certificates/* /etc/grid-security/certificates/

# Create globus directory where our user certificate will live (mount this to certificate on host)
RUN mkdir /root/.globus
