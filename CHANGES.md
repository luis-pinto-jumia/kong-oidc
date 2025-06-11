## Current Architecture Analysis

The current nokia/kong-oidc plugin uses a single OIDC configuration per plugin instance, with the main handler in `handler.lua` calling `utils.get_options(config, ngx)` to get a single OIDC configuration. The schema defines fields like `client_id`, `client_secret`, and `discovery` as single values rather than arrays.

## Multi-Provider Implementation Strategy

Here's how to modify the plugin to support multiple providers based on token issuer:## Key Implementation Changes

### 1. **Schema Modifications**
- Added `providers` array to support multiple OIDC configurations
- Each provider has its own `issuer`, `client_id`, `client_secret`, and `discovery` URL
- Added provider selection strategies: `token_issuer`, `header`, or `domain`
- Maintained backward compatibility with existing single-provider configurations

### 2. **Provider Selection Logic**
The enhanced `utils.lua` includes several selection strategies:

- **Token Issuer**: Extracts the `iss` claim from JWT Bearer tokens to match against configured providers
- **Header-based**: Uses a custom header (e.g., `X-OIDC-Provider`) to specify which provider to use
- **Domain-based**: Maps request domains to specific providers using `domain_provider_mapping`

### 3. **Configuration Examples**

Here are example configurations for different scenarios:

**Multiple Providers with Token Issuer Selection:**
```json
{
  "providers": [
    {
      "issuer": "https://auth.company1.com",
      "client_id": "kong-client-1",
      "client_secret": "secret-1",
      "discovery": "https://auth.company1.com/.well-known/openid-configuration"
    },
    {
      "issuer": "https://keycloak.company2.com/auth/realms/production",
      "client_id": "kong-client-2", 
      "client_secret": "secret-2",
      "discovery": "https://keycloak.company2.com/auth/realms/production/.well-known/openid-configuration"
    }
  ],
  "provider_selection_strategy": "token_issuer",
  "default_provider_issuer": "https://auth.company1.com"
}
```

**Header-based Provider Selection:**
```json
{
  "providers": [...],
  "provider_selection_strategy": "header",
  "provider_header_name": "X-OIDC-Provider"
}
```

**Domain-based Provider Selection:**
```json
{
  "providers": [...],
  "provider_selection_strategy": "domain",
  "domain_provider_mapping": {
    "api.company1.com": "https://auth.company1.com",
    "api.company2.com": "https://keycloak.company2.com/auth/realms/production"
  }
}
```

### 4. **Additional Enhancements**

- **Token Caching**: Prevents repeated JWT parsing for the same token
- **Custom Headers**: Each provider can inject custom headers based on token claims
- **Comprehensive Logging**: Better error messages and debug information
- **Fallback Support**: Multiple fallback mechanisms ensure reliability

### 5. **Migration Path**

The implementation maintains full backward compatibility. Existing configurations will continue to work without changes, while new multi-provider features are opt-in through the `providers` array configuration.

This approach allows you to gradually migrate from single-provider to multi-provider setups and provides flexibility for complex enterprise authentication scenarios where different services or tenants use different identity providers.