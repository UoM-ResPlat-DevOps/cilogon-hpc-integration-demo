FROM uomcilogon/gsissh_client

RUN yum -y install epel-release && yum clean all
RUN yum -y install python-pip

COPY requirements.txt requirements.txt
RUN pip install --upgrade pip
RUN pip install -r requirements.txt

COPY app/ /srv/app/

COPY start.sh start.sh
COPY init.sh init.sh
#ENTRYPOINT ["/start.sh"]
