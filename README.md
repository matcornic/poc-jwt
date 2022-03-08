# poc-jwt

Code is inspired from https://github.com/victorsteven/jwt-best-practices but contains lots of changes.

Implementation is inspired from these articles:

- https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/
- https://medium.com/monstar-lab-bangladesh-engineering/jwt-auth-in-go-part-2-refresh-tokens-d334777ca8a0
- https://indepth.dev/posts/1382/localstorage-vs-cookies
- https://learn.vonage.com/blog/2020/03/13/using-jwt-for-authentication-in-a-golang-application-dr/

JWT is nice to use, but can be tricky when you start to improve security using this kind of tokens.
We should not generate Tokens and store JWT tokens in the local storage. It can be used by malicious JS loaded on the page. And it cannot be revoked, unless revoking everyone by changing the secret. 

Instead, we create a pair of tokens at `/login`: the access token and the refresh token.
The access token is short-lived (e.g. 15 minutes), whether the refresh token is mean-lived (e.g. 1 week).

The access token will be stored in JS memory, whereas the refresh token will be stored in a HttpOnly Cookie (protection against XSS attacks).

The access token is passed through a classic Authorization Bearer on every protected route. As access token is short-lived, user would be disconnected after only 15min ! Here comes the Refresh token. When a protected route responds with a 401, we can call the /refresh route (with refresh access cookie), and the server will return new valid access and refresh tokens. 
This can be used to call the protected route. With JS, this can be transparent to the user.
When the refresh token has expired, the `/refresh` will also return a 401. It means the user has to login again.

In the implementation, tokens are stored in a fast access key-value database with TTL and authentication process uses it to check if it's valid. Tokens are stored with a TTL, so when the token disappears, it means it has expired. 
With this system, we can revoke refresh/access tokens if needed by deleting keys in the store. If our master secret is compromised, we can delete all keys and change the secret as well.

The `/logout` route removes access+refresh tokens from our database, invalidating the current session. As the refresh tokens is in a cookie, it's shared on a given browser. So it will logout the user for the current browser only. They will still be connected in other browsers
The `/logout-all-devices` route removes all tokens of the connected user, so they will have to authenticate again in all their devices.
