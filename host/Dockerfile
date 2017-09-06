FROM jbasney/globus
RUN yum -y update && yum -y install git wget gsi-openssh-server \
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

# Custom config to set SSH port to 2222, block password auth
COPY sshd_config /etc/gsissh/sshd_config

# Utility for setting up host certificate once container up
COPY get_host_cert.sh /get_host_cert.sh
RUN chmod +x get_host_cert.sh

# ... and wrapper for kicking off gsisshd
COPY start_host.sh /start_host.sh
RUN chmod +x start_host.sh

# An example user that we might want our client to login as via certificate
RUN adduser test-user

# Unfortunately have to set a password for account to be unlocked, even though password SSH disabled.
RUN echo 'password' | passwd test-user --stdin
