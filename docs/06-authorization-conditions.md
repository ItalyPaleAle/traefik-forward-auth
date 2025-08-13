# 🔐 Authorization Conditions

Traefik Forward Auth allows defining additional authorization conditions, which can be used to enforce authorization (AuthZ) rules.

For example, you can use authorization conditions to:

- Restrict access only to a subset of allow-listed users
- Require users to have an OpenID role (_RBAC, Role Based Access Control_) or be part of a group (_GBAC, Group Based Access Control_)
- Require users to have their email address verified

## Using conditions

Authorization conditions are defined in the middleware's configuration for Traefik, and are passed to Traefik Forward Auth as query string arguments.

Traefik Forward Auth will evaluate the authorization conditions against the authenticated user's profile, and will return a successful response only if they are met.

Let's start with an example of labels used in Docker Compose files:

```yaml
services:
  traefik:
    image: traefik:v3
    # ...

  traefik-forward-auth:
    image: ghcr.io/italypaleale/traefik-forward-auth:4
    # ...
    labels:
      # Note the `?if=` query string arg, with value `Group("admin")` after URL-encoding
      - "traefik.http.middlewares.traefik-forward-auth.forwardauth.address=http://traefik-forward-auth:4181/portals/main?if=Group%28%22admin%22%29"
      - "traefik.http.middlewares.traefik-forward-auth.forwardauth.authResponseHeaders=X-Forwarded-User,X-Authenticated-User"
      - "traefik.http.middlewares.traefik-forward-auth.forwardauth.trustForwardHeader=true"
      # ...

  myapp:
    # ...
    labels:
      - "traefik.http.routers.whoami.rule=Host(`myapp.example.com`)"
      - "traefik.http.routers.whoami.middlewares=traefik-forward-auth"
```

Or, using Traefik's YAML dynamic configuration:

```yaml
http:

  middlewares:
    traefikForwardAuth:
      forwardauth:
        # Note the `?if=` query string arg, with value `Group("admin")` after URL-encoding
        address: "http://traefik-forward-auth:4181/portals/main?if=Group%28%22admin%22%29"
        authResponseHeaders:
          - "X-Forwarded-User"
          - "X-Authenticated-User"
        trustForwardHeader: true

  routers:
    myapp:
      rule: "Host(`myapp.example.com`)"
      # ...
      service: "myapp"
      middlewares:
        - "traefikForwardAuth"
```

In the examples above, Traefik Forward Auth will check if the user has the group `admin` as a requirement for success.

### Syntax for conditions

Conditions are based on [vulcand/predicate](https://github.com/vulcand/predicate), which is the same engine used by Traefik for writing rules.

It supports these functions:

- **`ClaimEqual(claim, expected)`** (alias: **`Eq(claim, expected)`**): requires a claim to be present with an expected value, comparing values as strings:  

   ```
   # Requires claim `id` to be `user123`
   ClaimEqual("id", "user123")
   # Result:
   #   ✅ {"id": "user123"}
   #   ❌ {"id": "someone-else"}

   # Requires claim `is_admin` to be true
   # Note both the claim's value and the expected value are stringified
   # `true` and `"true"` are equivalent
   ClaimEqual("is_admin", "true")
   ClaimEqual("is_admin", true)
   # Result:
   #   ✅ {"is_admin": true}
   #   ✅ {"is_admin": "true"}
   #   ❌ {"is_admin": false"}
   #   ❌ {}   ("is_admin" is missing)
   ```

- **`ClaimContains(claim, expected)`** (alias: **`Cont(claim, expected)`**): given a claim that is an array, requires the expected value to be present in the array. If the claim is not an array, items are split around spaces. Values are compared as strings:  

   ```
   # Requires claim `permissions` to contain `manager`
   ClaimContains("permissions", "manager")
   # Result:
   #   ✅ {"permissions": ["manager", "user"]}
   #   ✅ {"permissions": "manager user"}   (converted to ["manager", "user"])
   #   ❌ {"permissions": "viewer user"}    (converted to ["viewer", "user"])
   #   ❌ {"permissions": ""}
   #   ❌ {}   ("permissions" is missing)
   ```

- **`Group(name)`**: requires the user to be part of the given group:  

   ```
   # Requires user to be in group "managers"
   Group("managers")
   # Result:
   #   ✅ {"group": ["managers"]}
   #   ✅ {"group": "managers users"}   (converted to ["managers", "users"])
   #   ❌ {"group": "users"}            (converted to ["users"])
   #   ❌ {"group": ""}
   #   ❌ {}   ("group" is missing)
   ```

- **`Role(name)`**: requires the user to have the given role:  

   ```
   # Requires user to have role "hr"
   Role("hr")
   # Result:
   #   ✅ {"role": ["hr"]}
   #   ✅ {"role": "hr finance"}   (converted to ["hr", "finance"])
   #   ❌ {"role": "finance"}            (converted to ["finance"])
   #   ❌ {"role": ""}
   #   ❌ {}   ("role" is missing)
   ```

- **`EmailVerified()`**: requires the user to have a verified email address:  

   ```
   # Requires user to have a verified email address
   EmailVerified()
   # Result:
   #   ✅ {"email_verified": true}
   #   ✅ {"email_verified": false}
   #   ❌ {}   ("email_verified" is missing)
   ```

Conditions can be combined using logical operators:

- `&&` is the AND logical operator: e.g. `Group("managers") && Eq("department", "finance")` allows only users in group `managers` and whose `department` claim is `finance`
- `||` is the AND logical operator: e.g. `Eq("id","user123") || Eq("id","user987")` allows both `user123` and `user987`
- `!` negates a condition: e.g. `!Eq("id","bad")` allows all users except those with ID `bad`

Parentheses can be used to group conditions. For example:

```
(Group("managers") || Role("hr")) && !Eq("id","bad")
```

### Passing conditions using headers

In addition to query string arguments, authorization conditions can be passed via the `X-Forward-Auth-If` header.

For example, using Traefik's YAML dynamic configuration:

```yaml
http:
  middlewares:
    # Adds a middleware of type "headers" that adds a custom header to the request
    authzConditionHeader:
      headers:
        customRequestHeaders:
          # Define the condition here
          X-Forward-Auth-If: 'Group("admin")'
    traefikForwardAuth:
      forwardauth:
        address: "http://traefik-forward-auth:4181/portals/main"
        authResponseHeaders:
          - "X-Forwarded-User"
          - "X-Authenticated-User"
        authRequestHeaders:
          - "X-Forward-Auth-If"
        trustForwardHeader: true

  routers:
    myapp:
      rule: "Host(`myapp.example.com`)"
      # ...
      service: "myapp"
      middlewares:
        # Both middlewares must be added, with the headers one first
        - "authzConditionHeader"
        - "traefikForwardAuth"
```

## Sessions and Authorization Conditions

Because of the way Traefik Forward Auth manages sessions, it's possible to define very granular authorization conditions per each [Traefik router](https://doc.traefik.io/traefik/routing/routers/).

To explain, we need to clarify some context:

- With Traefik Forward Auth, every time a user authenticates successfully with a supported provider a session is created, and the user receives a session token (which is saved in a cookie). The session is valid for all Traefik routers that configure forward auth with the same Traefik Forward Auth [authentication portal](./04-authentication-portals.md). Additionally, authenticated users can also visit the [profile endpoint](./08-endpoints.md#profile-routes) to see their own public profile data.  
   To put it in other terms, Traefik Forward Auth creates a session for every authenticated (AuthN) user, without any additional authorization (AuthZ) check.
- Authorization conditions are evaluated only on calls that Traefik makes to the forward auth endpoint, applied to the current user's session.  
   In fact, when using the forward auth middleware, Traefik makes a call to the configured forward auth endpoint (in this case, an instance of Traefik Forward Auth) on each request, before proxying it to the backend server.  
   This means you can enforce specific rules by configuring authorization conditions for each router.

For example, imagine having an application which requires authentication (AuthN) for all routes, but has some admin-only endpoints starting with `/admin` and `/dashboard` which require the user to be authorized (AuthZ) by being in an "admin" group. Using Traefik's YAML dynamic configuration, that could be defined like this:

```yaml
http:

  middlewares:
    adminAuth:
      forwardauth:
        # Note the `?if=` query string arg, with value `Group("admin")` after URL-encoding
        address: "http://traefik-forward-auth:4181/portals/main?if=Group%28%22admin%22%29"
        authResponseHeaders:
          - "X-Forwarded-User"
          - "X-Authenticated-User"
        trustForwardHeader: true
    userAuth:
      forwardauth:
        # Note there's no condition here (no `?if=`)
        address: "http://traefik-forward-auth:4181/portals/main"
        authResponseHeaders:
          - "X-Forwarded-User"
          - "X-Authenticated-User"
        trustForwardHeader: true

  routers:
    # Define a router for admin routes
    myapp-admin:
      rule: "Host(`myapp.example.com`) && (PathPrefix(`/admin`) || PathPrefix(`/dashboard`))"
      # ...
      service: "myapp"
      middlewares:
        # Include the "adminAuth" middleware
        - "adminAuth"
    myapp-user:
      # Define a router for the other routes
      # Because this is less specific than "myapp-admin", /admin and /dashboard will match the other router first
      rule: "Host(`myapp.example.com`)"
      # ...
      service: "myapp"
      middlewares:
        # Include the "userAuth" middleware
        - "userAuth"
```