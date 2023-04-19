# l9g-encrypted-user-password

We are in a transition to OpenID Connect authentication with all of our services. 

But there are productiv legacy and 3rd party services that can only be accessed by username/password credentials.

So i decided to write this Keycloak "Authentication Provider" to get access to the *plain users password* (clear text password) but in a secure way. 

## build
- run `mvn package` (Maven)

## prepare
- create the public and private keypair with the keygen tool.
  - the `l9g-encrypted-user-password-keygen.jar` file sould be direct executable

## keycloak server
- copy the `l9g-encrypted-user-password-provider.jar` and the generated `l9g-encrypted-user-password-server.publickey` into `keycloak/providers` directory.
- restart keycloak
- add `L9G Encrypted User Password` Authorization Step after the `User Password Form` in your authentication flow.
- The provider encrypts the plain user password with the Elliptic Curve Algorithm (PublicKey) and stores it in the users attributes named `ENCRYPTED_USER_PASSWORD`
- add a User Attribute Mapper for `ENCRYPTED_USER_PASSWORD` (idToken) to your Client specific scope.

## OIDC Client
- copy the `l9g-encrypted-user-password-client.pirvatekey` to your trusted client and use the Elliptic Curve Algorithm (PrivateKey) to decrypt the password.
- In Java i've been working with the BouncyCastle provider. 