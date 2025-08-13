# 📍 Endpoints

- [Profile routes](#profile-routes)
- [APIs](#apis)

## Profile routes

Traefik Forward Auth exposes a route **`/portal/<portal>/profile`** that all logged-in users can access to view their own profile, returning the information included in the JWT token in the cookie.

For example, if Traefik Forward Auth is listening on `https://auth.example.com/` and the authentication portal's name is `main`, visit `https://auth.example.com/portal/main/profile` to view information such as:

```text
Authenticated

ID: cf81e854-5289-4124-a3f6-ead700cfd192
Provider: mygoogle
Name:
   Full Name: Alessandro Segala
   First: Alessandro
   Last: Segala
Email:
   Address: alessandro@example.com
   Verified: true
Picture: https://example.com/cf81e854-5289-4124-a3f6-ead700cfd192/profile-picture.png
Groups:
  - 32908b2b-82f2-49af-b114-e25c968b6f5f
  - d589a634-6403-442d-901a-98c286576410
```

The same data is also available in JSON format at **`/portal/<portal>/profile.json`** (note the `.json` suffix). For example:

```json
{
  "authenticated": true,
  "provider": "mygoogle",
  "id": "cf81e854-5289-4124-a3f6-ead700cfd192",
  "name": {
    "full": "Alessandro Segala",
    "first": "Alessandro",
    "last": "Segala"
  },
  "email": {
    "address": "alessandro@example.com",
    "verified": true
  },
  "picture": "https://example.com/cf81e854-5289-4124-a3f6-ead700cfd192/profile-picture.png",
  "groups": [
    "32908b2b-82f2-49af-b114-e25c968b6f5f",
    "d589a634-6403-442d-901a-98c286576410"
  ]
}
```

The information presented on these pages depends on what was shared by the identity provider. It never includes confidential fields such as passwords or other secrets.

## APIs

### `GET /api/portals/<portal>/verify`

The `GET /api/portals/<portal>/verify` validates a token and returns the list of claims it includes, providing the same information as the [profile routes](#profile-routes).

The token can be passed in the `Authorization` header.

The method returns a JSON-encoded response that includes the claims extracted from the token. For example:

```sh
curl -H "Authorization: Bearer <token>" https://auth.example.com/api/portals/main/verify
```

Response will be similar to:

```json
{
  "valid": true,
  "portal": "main",
  "provider": "mygoogle",
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
    "iss": "traefik-forward-auth/google",
    "name": "Alessandro Segala",
    "nbf": "2025-03-16T03:10:17Z",
    "picture": "https://example.com/cf81e854-5289-4124-a3f6-ead700cfd192/profile-picture.png",
    "sub": "cf81e854-5289-4124-a3f6-ead700cfd192"
  }
}
```
