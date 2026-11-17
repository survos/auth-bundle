# OAuth resource servers

This integration is opt-in. Existing form login, social login, OIDC browser account
linking and development auto-login are unchanged. Browser SSO remains configured
with Symfony `oidc_login`; resource principals never create or link local accounts.

Requires Symfony Security 8.2+ (including OAuth2ScopeVoter and protected resource
metadata), Symfony HttpClient and `web-token/jwt-library:^4.0`. These requirements
are checked only when a resource is enabled. The bundle's existing consumers do
not have to upgrade just to keep using browser login.

```yaml
survos_auth:
    authorities:
        authentik:
            issuer: '%env(CORPUS_AUTH_ISSUER)%'
    resources:
        corpus:
            enabled: true
            authority: authentik
            path: /mcp/corpus
            resource: '%env(CORPUS_RESOURCE_URI)%'
            audiences: ['%env(CORPUS_RESOURCE_URI)%']
            required_scopes: ['corpus:read']
```

The resource name becomes the firewall name. Choose a unique name; do not reuse
`main` or redefine this firewall in application security configuration. The bundle
prepends an exact-path stateless firewall and scope access rule ahead of existing
catch-alls. Every listed scope is required (AND). The public metadata path is
`/.well-known/oauth-protected-resource` plus the resource path. Keep the application's
existing import of `security.route_loader`, or add:

```yaml
# config/routes/security.yaml
security:
    resource: security.route_loader
    type: service
```

Issuer and canonical resource must be HTTPS URLs without credentials, queries or
fragments. The resource URL's path must equal `path`. Environment placeholders are
resolved at container compilation; rebuild the container after changing them.
An explicit `enabled: false` bypasses issuer/resource resolution, permitting an
unprovisioned deployment to retain its current security configuration.

Symfony owns bearer extraction, RS256 signature verification, discovery/JWKS
caching, required issuer/audience/time claims, and access-token type enforcement
(`at+jwt` or `application/at+jwt`). Only the Authorization header is accepted.
Missing/invalid credentials return 401; insufficient scope returns 403. Symfony
publishes RFC 9728 metadata and advertises it in its bearer challenges. There is no
custom cryptographic implementation or token minting in this bundle.

The custom user provider is intentionally small: it returns an ephemeral principal
identified by the validated `(iss, sub)` pair. It ignores email and roles claims,
grants no application roles, and refuses session refresh. It must only be used
behind the validating access-token authenticator. Scopes remain the permission
boundary; resource authentication is not a grant of browser/admin access.

## Issuer provisioning and compatibility

Create separate environment/client registrations. Prove the issuer emits the
resource audience, `corpus:read`, a short expiry and access-token type before
enabling the resource. Authentik browser registrations with `openid email profile`
alone do not satisfy this contract. Generic `typ: JWT` tokens are rejected; do not
disable token-type checks to make browser ID tokens pass. No real Authentik access
token or client registration has been provisioned or verified by this change.

Service accounts get their own identity and least-privilege grant. Clients obtain
and renew access tokens from Authentik; a bearer-token environment variable in an
MCP client does not automatically implement renewal. Local signature validation
does not provide immediate revocation: use short token lifetimes and verify the
JWKS cache/rotation behavior before rotating signing keys. Introspection would be
a separate future opt-in mode if immediate revocation becomes necessary.

Test actual MCP clients separately: metadata discovery, registration/pre-registration,
PKCE, redirect handling, resource indicators, token renewal, and SDK transport
compatibility. This integration provides the resource-server side, not an OAuth
authorization server or client registration service. No credentials are needed by
the API server for public JWKS validation.

For corpus-only production servers using command-bundle, set
`survos_command.agent.enabled: false`. Its loader registers command tools outside
the MCP registry's namespace filter. This disables all command MCP tools in that
environment (including STDIO), not their console commands. Keep it enabled in dev
if local diagnostics are wanted. Existing default is true for compatibility.

## Verification

`tests/ResourceSecurityTest.php` exercises a real Symfony HTTP firewall with an
isolated, in-memory issuer and ephemeral signing key. It verifies success, public
metadata, scope denial, missing credentials, cookie isolation, ignored role claims,
statelessness, issuer/audience/time checks, ID-token rejection, signature tampering
and sender-constrained token rejection. No live credentials or network are used.
