# cilogon-hpc-integration-demo

A demonstration project showing how to get your web app to authenticate with a HPC cluster using CILogon.

## The Problem

You've built a web app to serve a community of researchers. But some of the tasks it performs are compute-intensive, and you'd like to run them on a supercomputer (i.e. HPC) instead of the infrastructure hosting your app.

Your users have HPC accounts, but how does your app logon on their behalf to submit jobs? You could ask for their password, but this comes with great responsibility, and may be prohibited by your host institution. Or you could have the user set up an SSH keypair for your app to use, but you still need to protect those keys, rotate them periodically, and get your users (who may not be comfortable with the command line) get create them in the first place.

## Solution: CILogon + x509 Certificates
Instead of passwords and keypairs, we can use short-term certificates. This identifies the user, allowing them to be linked to a local HPC account. The certificates have a limited lifespan, and so don't need to be manually cycled like passwords and plain keypairs.

CILogon provide a hosted service that joins institutional identity providers (including AAF via eduGain) with OpenID Connect, and provides an API endpoint that can issue certificates linked to these identities for authentication over SSH, which we can then use to kick off HPC jobs or transfer files.

Not that the user needs to be aware of any of this; in the ideal case, they simply link their HPC account via it's user management GUI, and log into your app using their local institution credentials.

# Jargon

Distinguished Name (DN)
User Certificate
Host Certificate
Certificate Authority
GSI
OAuth2


## Example Workflow

1. User logs into the user management system of their preferred HPC cluster, and sets the distinguished name (DN) of certificates that will subsequently be issued to them. They can do this manually, or simply be walked through a CILogon OAuth2 authentication process (with their institutional credentials) so the HPC cluster can look up the DN on their behalf.

2. The user authenticates with your web app, and uses it to submit a HPC job.

3. Your web app requests a short-term certificate on behalf of the user via CILogon. The certificate stays within the backend of your web app, the user never needs to download it, or even know that it's there.

4. Your web app authenticates with the HPC cluster using the certificate. The HPC cluster, knowing about the certificate identity from step 1, accepts it and logs in under the native user account.

5. Your web app transfers any necessary files, submits a HPC job, and when complete, fetches the results for display in your app.


## Ingredients

*User*
To use HPC via your app, all your user should need is:

* Local Institution Credentials: CILogon links with global research and educational identity providers via eduGain. Support for Australian universities via the AAF is in progress, and Google credentials can be used as well if need be.
* Web Browser: Ideally your users can kick off HPC jobs without ever leaving their browser.


*Web App*
Your web app needs the following components for this to work:

* gsissh client: gsissh is a fork of OpenSSH that supports certificates. This can be installed alongside the existing system OpenSSH.
* CA certificates: Your host needs to know about the certificate authorities for CILogon (client certificate) and Let's Encrypt (host certificate).
* OAuth2 Client: You need to register your application with CILogon (https://cilogon.org/oauth2/register) so you may use them as an OAuth2 provider. OAuth2 libraries are available for most languages; we use Requests-OAuthlib for Python.

*HPC Service*
Changes to the HPC services you wish to target are necessary for this to work, which is likely to be the sticking point for achieving integration. Allow plenty of time to consult, develop and test a solution with your system administrators. Requirements include:

* gsissh server: This can run alongside your existing ssh server (for instance, on port 2222) and be locked down if necessary (e.g. to specific client IP addresses).
* Host certificate: Since we're not joining a bigger consortium, a certificate issued by Let's Encrypt will suffice.
* CA certificates: Your host needs to know about the Let's Encrypt and CILogon certificate authorities.
* Manage grid-mapfile: Your cluster needs a way to associate user certificate DNs with native posix user accounts, which is typically via `/etc/grid-security/grid-mapfile`. This file could be managed manually, or integrated with an existing account management system for self-service.


## Deploying gsissh host

A simple Docker container is provided as an example. In production, you're more likely to install/configure directly on an existing (or additional) login node which has access to the rest of your cluster, including mounts and the scheduler.

To get a demo host going:

1. Provision a host (for example, a Nectar VM), and install Docker. 
* You'll need a proper domain name for this host (i.e. your local machine is probably not suitable).
* Allow incoming connections on port 2222 (which we'll use for gsissh) and 443 (to allow Let's Encrypt to verify domain ownership when issuing host certificate).

2. Setup a domain/subdomain for your host. 

`sudo docker pull uomcilogon/gsissh_host`

4. Pull and then start container, exposing ports 2222/443, and a volume where host certificates can be persisted (create a `letsencrypt-certs` directory on host if it doesn't already exist).

In the container, we'll run a helper script which requests certificate and makes it available to gsissh server. Substitute in your email address, and the domain you created in step 2.

`sudo docker run -it -p 2222:2222 -p 443:443 -v ~/letsencrypt-certs:/etc/letsencrypt uomcilogon/gsissh_host ./get_host_cert.sh me@example.com myhost.com`

It's possible that a reverse DNS lookup on your host will pickup another domain name owned by your infrastructure provider (e.g. something like `vm-123-123-123-123.cloud.com`), in which cas you should include that as well so that the certificate request doesn't fail. That is, use this at the end od the command instead.

`./get_host_cert.sh me@example.com myhost.com vm-123-123-123-123.cloud.com`

6. Create an empty `grid-mapfile` on your host -- this will be where we map certificate DNs to native users within the container. An example user (`test-user`) is already included in  the `uomcilogon/gsissh_host`.
 
`touch ~/grid-mapfile`
 
 
5. Let's run again with our gsissh server. We'll keep the mount where our host certificates live, and also expose `grid-mapfile`. We'll keep this running in the background, ready for use!
 
`sudo docker run -it -p 2222:2222 -v ~/letsencrypt-certs:/etc/letsencrypt -v ~/grid-mapfile:/etc/grid-security/grid-mapfile -d uomcilogon/gsissh_host ./start_host.sh`


6. Before anyone can connect to our gsissh server, we need to add some entries to the grid-mapfile on our host like so:
 
`echo '"/DC=org/DC=cilogon/C=US/O=Google/CN=Some Person A123456" test-user' >> ~/grid-mapfile`

7. Done! 


**N.B.** You'll have to periodically renew your Let's Encrypt certificate (they expire after 90 days), which you can do by repeating step 4.


## Deploying gsissh client

Again, we provide a simple Docker container as an example. Unlike the server, you may well want to bake this into your app to avoid installing and configuring gsissh from scratch.

1. Get a user certificate, using either the CILogon OpenID Connect API endpoint (http://www.cilogon.org/oidc), or manually at https://cilogon.org/ (which will be protected with a password).

2. Pull the client container, and start a bash session. Replace `~/my_certificate.p12` with the name and path to the certificate you requested above. This is for the sake of demonstration, but in your end application you might wrap the following in a single script, along with the tasks you intend to perform on the gsissh host once logged in. 

`sudo docker run -it -v ~/my_certificate.p12:/root/.globus/usercred.p12 uomcilogon/gsissh_client bash`

3. Ensure the DN for the certificate you requested in step 1 has been added to `grid-mapfile` as per previous section.

4. Restrict permissions on your certificate to keep `gsissh` happy.

`chmod 600 /root/.globus/usercred.p12`

5. Create a proxy certificate, providing a password if necessary (i.e. if you requested your certificate manually from https://cilogon.org/). Once this proxy certificate is created, you won't need to enter a password to use it again for 12 hours.

`grid-proxy-init`

6. Connect to your host and get to work!

`gsissh -p 2222 test-user@myhost.com`


## Deploying demo web app
This is a simple web app (based on Flask) that exercises the above, allowing you to start a program on a remote host, authenticating via certificates obtained from CILogon.

1. 

`sudo docker run  -v ~/my_certificate.p12:/root/.globus/usercred.p12 -p 4000:4000 uomcilogon/demo_app`


To run with code located outside container (for live development), run within `example_client_app` folder:

`docker run  -v ~/my_certificate.p12:/root/.globus/usercred.p12 -p 4000:4000 -v $(pwd)/app:/srv/app/ -it uomcilogon/demo_app bash`

base oauth2 cilogon workflow on:

http://bitwiser.in/2015/09/09/add-google-login-in-flask.html


start with `sudo docker run -it -p 443:4000 -e CLIENT_SECRET=... uomcilogon/demo_app bash`

create initial database with
```
cd /srv/app/
python
from app import db
db.create_all() # does this overwrite if existing database?
```

create self signed certs (todo: switch to let's encrypt)

`openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /selfsigned.key -out /selfsigned.crt`

and then run with `start.sh`



# Troubleshooting

* Use debug option when creating proxy certificate to make sure paths and permissions are correct `grid-proxy-init -debug`
* Try kicking off the host manually with `/sbin/gsisshd -debug`, which will let you know where things are going wrong. Similarly on client side, use `-v` for more verbose debugging (adding extra `v`'s as needed to increase verbosity).


## Demonstration

This repository includes a simple example web app that can kick off a HPC job on behalf of a user via CILogon. It's built with plain 'ol jQuery/Boostrap on the frontend, and using Flask, a simple Python web framework, on the backend.

It's intended to be a launching point for your own science app, rather than a useful tool in of itself!

Live demo here.

(instructions on kicking off your own instance)

