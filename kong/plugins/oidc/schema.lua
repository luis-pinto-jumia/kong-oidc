return {
  no_consumer = true,
  fields = {
    -- Legacy single provider support (for backwards compatibility)
    client_id = { type = "string", required = false },
    client_secret = { type = "string", required = false },
    discovery = { type = "string", required = false },
    
    -- New multi-provider configuration
    providers = {
      type = "array",
      required = false,
      elements = {
        type = "record",
        fields = {
          issuer = { type = "string", required = true },
          client_id = { type = "string", required = true },
          client_secret = { type = "string", required = true },
          discovery = { type = "string", required = true },
          introspection_endpoint = { type = "string", required = false },
          timeout = { type = "number", required = false },
          introspection_endpoint_auth_method = { type = "string", required = false },
          token_endpoint_auth_method = { type = "string", required = false, default = "client_secret_post" },
          scope = { type = "string", required = false, default = "openid" },
          response_type = { type = "string", required = false, default = "code" },
          ssl_verify = { type = "string", required = false, default = "no" },
          realm = { type = "string", required = false, default = "kong" },
          session_secret = { type = "string", required = false },
          -- Provider-specific headers
          header_names = { type = "array", elements = { type = "string" }, required = false },
          header_claims = { type = "array", elements = { type = "string" }, required = false }
        }
      }
    },
    
    -- Global settings
    bearer_only = { type = "string", required = true, default = "no" },
    realm = { type = "string", required = true, default = "kong" },
    redirect_uri_path = { type = "string" },
    scope = { type = "string", required = true, default = "openid" },
    response_type = { type = "string", required = true, default = "code" },
    ssl_verify = { type = "string", required = true, default = "no" },
    token_endpoint_auth_method = { type = "string", required = true, default = "client_secret_post" },
    session_secret = { type = "string", required = false },
    timeout = { type = "number", required = false },
    introspection_endpoint = { type = "string", required = false },
    introspection_endpoint_auth_method = { type = "string", required = false },
    recovery_page_path = { type = "string", required = false },
    
    -- Provider selection strategy
    provider_selection_strategy = { 
      type = "string", 
      required = false, 
      default = "token_issuer",
      one_of = { "token_issuer", "header", "domain" }
    },
    
    -- Default provider (fallback)
    default_provider_issuer = { type = "string", required = false },
    
    -- Header-based provider selection
    provider_header_name = { type = "string", required = false, default = "X-OIDC-Provider" },
    
    -- Domain-based provider mapping
    domain_provider_mapping = {
      type = "map",
      keys = { type = "string" },
      values = { type = "string" },
      required = false
    }
  }
}