FROM uomcilogon/gsissh_client

RUN yum -y install epel-release && yum clean all
RUN yum -y install python-pip

COPY requirements.txt requirements.txt
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

COPY app/ /srv/app/

# Utility for setting up host certificate once container up
# This time used for HTTPS, not gsissh host certs
# Should put this somewhere common since duplicated with host container :-(
COPY get_host_cert.sh /get_host_cert.sh

COPY start.sh start.sh
COPY init.sh init.sh
#ENTRYPOINT ["/start.sh"]
