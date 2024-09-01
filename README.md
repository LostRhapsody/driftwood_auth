# Driftwood Auth
This is simple a supplementary library for Driftwood.

For the client (That's the driftwood desktop app) to safely authenticate via OAuth2.0 and Netlify, we need this small program to run on the web server.

## Basic workflow
The client requests a token, sending a public key to the web server. The web server triggers the authorization flow. The user logs in, and Netlify sends the token to the secure web server. The server will then encrypt the token using the public key, which only the client can decrypt with it's private key.
The encyrpted token is sent to the client, where it's decrypted and stored securly for making API requests.
