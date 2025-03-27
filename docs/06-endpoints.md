# 📍 Endpoints

- [Profile route](#profile-route)
- [APIs](#apis)

## Profile route

Traefik Forward Auth exposes a route `/profile` that all logged-in users can access to view their own profile, returning the information included in the JWT token in the cookie.

For example, if Traefik Forward Auth is listening on `https://auth.example.com/`, visit `https://auth.example.com/profile` to view information such as:

```text
Authenticated

ID: cf81e854-5289-4124-a3f6-ead700cfd192
Name:
   Full Name: Alessandro Segala
   First: Alessandro
   Last: Segala
Email:
   Address: alessandro@example.com
   Verified: true
Picture: https://example.com/cf81e854-5289-4124-a3f6-ead700cfd192/profile-picture.png
```

The information presented on the page depends on what was shared by the identity provider. It never includes confidential fields such as passwords or other secrets.

## APIs

### `GET /api/verify`

The `GET /api/verify` validates a token and returns the list of claims it includes, providing the same information as the [profile route](#profile-route).

The token can be passed in the `Authorization` header.

The method returns a JSON-encoded response that includes the claims extracted from the token. For example:

```sh
curl -H "Authorization: Bearer <token>" https://auth.example.com/api/verify
```

Response will be similar to:

```json
{
  "valid": true,
  "claims": {
    "aud": [
      "auth.example.com"
    ],
    "email": "alessandro@example.com",
    "email_verified": true,
    "exp": "2025-03-16T05:10:18Z",
    "family_name": "Segala",
    "given_name": "Alessandro",
    "iat": "2025-03-16T03:10:17Z",
    "iss": "traefik-forward-auth/openidconnect",
    "name": "Alessandro Segala",
    "nbf": "2025-03-16T03:10:17Z",
    "picture": "https://example.com/cf81e854-5289-4124-a3f6-ead700cfd192/profile-picture.png",
    "sub": "cf81e854-5289-4124-a3f6-ead700cfd192"
  }
}
```
