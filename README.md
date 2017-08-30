# cilogon-hpc-integration-demo

A demonstration project showing how to have your web app authenticate with a HPC cluster using CILogon.

## The Problem

You've built a web app to serve a community of researchers. But some of the tasks it performs are incredibly compute-intensive, and you'd like to run them on a supercomputer (i.e. HPC) instead of the infrastructure hosting your app.

Your users have HPC accounts, but how does your app logon on their behalf to submit jobs? You could ask for their password, but this comes with great responsibility, and may be prohibited by your host institution. Or you could have the user set up an SSH keypair for your app to use, but you still need to protect it and have users set it up for you. 

## Solution: CILogon + x509 Certificates
Instead of passwords and plain keypairs, we can use short-term certificates. This identifies the user, allowing them to be linked to a local HPC account. The certificates have a limited lifespan, and so don't need to be manually cycled like passwords and plain keypairs.

CILogon provide a hosted service that joins institutional identity providers (including AAF via eduGain) with OpenID Connect, and provides an API endpoint that can issue certificates linked to these identities for authentication over SSH, which we can then use to kick off HPC jobs or transfer files.

## Example Workflow

1. Use logs into the user management system of their preferred HPC cluster, and sets the distinguished name (DN) of certificates that will subsequently be issued to them. They can do this manually, or simply be walked through a CILogon OAuth2 authentication process (with their institutional credentials) so the HPC cluster can look up the DN on their behalf.

2. The user authenticates with your web app, and uses it to submit a HPC job.

3. Your web app requests a short-term certificate on behalf of the user via CILogon. The certificate stays within the backend of your web app, the user never needs to download it, or even know that it's there.

4. Your web app authenticates with the HPC cluster using the certificate. The HPC cluster, knowing about the certificate identity from step 1, accepts it and logs in under the native user account.

5. Your web app transfers any necessary files, submits a HPC job, and when complete, fetches the results for display in your app.


## Ingredients

*User*
To use HPC via your app, all your user needs is:

* Local Institution Credentials: CILogon links with global research and educational identity providers via eduGain. Support for Australian universities via the AAF is in progress, and Google credentials can be used as well if need be.
* Web Browser: Ideally your users can kick off HPC jobs without ever leaving their browser!


*Web App*
Your web app needs the following components for this to work:

* gsissh client: gsissh is a fork of OpenSSH that supports certificates. This can be installed alongside the existing system OpenSSH.
* CA certificates: Your host needs to know about certificates issued by CILogon (client certificate) and Let's Encrypt (host certificate).
* OAuth2 Client: You need to register your application with CILogon (link) so you may use them as an OAuth2 provider. OAuth2 libraries are available for everywhere; we use Requests-OAuthlib for Python.

*HPC Service*
Some additions to the HPC services you wish to target are necessary for this to work, which is likely to be the sticking point. That being said, gsissh is widely used across grids worldwide (albeit not so much in Australia), and so isn't breaking new ground.

* gsissh server: As above, but the server side. This can run alongside your existing ssh server (for instance, on port 2222) and be locked down if necessary (e.g. to specific client IP addresses).
* Host certificate: Since we're not joining a bigger consortium, a certificate issued by Let's Encrypt will do just fine.
* CA certificates: Your host needs to know about the Let's Encrypt and CILogon certificate authorities.
* Manage grid-mapfile: 



## Demonstration

This repository includes a simple example web app that can kick off a HPC job on behalf of a user via CILogon. It's built with plain 'ol jQuery/Boostrap on the frontend, and using Flask, a simple Python web framework, on the backend.

It's intended to be a launching point for your own science app, rather than a useful tool in of itself!

Live demo here.

(instructions on kicking off your own instance)

