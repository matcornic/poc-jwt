# poc-jwt

Code is inspired from https://github.com/victorsteven/jwt-best-practices but contains lots of changes.

JWT is nice to use, but can be tricky when you start to improve security using this kind of tokens.
We should not generate Tokens and store JWT tokens in the local storage. It can be used by malicious JS loaded on the page. And it cannot be revoked, unless revoking everyone by changing the secret. 

Instead, we create a pair of tokens at /login: the access token and the refresh token.
The access token is short-lived (e.g. 15 minutes), whether the refresh token is mean-lived (e.g. 1 week).

The access token will be stored in JS memory, whereas the refresh token will be stored in a HttpOnly Cookie (protection against XSS attacks).

The access token is passed through a classic Authorization Bearer on every protected route. As access token is short-lived, user would be disconnected after only 15min ! Here comes the Refresh token. When a protected route responds with a 401, we can call the /refresh route (with refresh access cookie), and the server will return a new valid access token. This can be used to call the protected route. With JS, this can be transparent to the user.
When the refresh token has expired, the /refresh will also return a 401. It means the user has to login again.

In the implementation, tokens are stored in a fast access key-value database with TTL and authentication process uses it to check if it's valid. Tokens are stored with a TTL, so when the token disappears, it means it has expired. 
With this system, we can revoke refresh/access tokens if needed by deleting keys in the store. If our master secret is compromised, we can delete all keys and change the secret.
