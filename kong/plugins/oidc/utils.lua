local cjson = require "cjson"
local url = require "socket.url"

local M = {}

-- Cache for decoded tokens to avoid repeated parsing
local token_cache = {}

-- Parse JWT token without verification to extract issuer
local function parse_jwt_payload(token)
  if token_cache[token] then
    return token_cache[token]
  end
  
  local parts = {}
  for part in string.gmatch(token, "[^%.]+") do
    table.insert(parts, part)
  end
  
  if #parts ~= 3 then
    return nil, "Invalid JWT format"
  end
  
  -- Base64 decode the payload (second part)
  local payload_b64 = parts[2]
  -- Add padding if needed
  local padding = 4 - (#payload_b64 % 4)
  if padding ~= 4 then
    payload_b64 = payload_b64 .. string.rep("=", padding)
  end
  
  local success, payload_json = pcall(ngx.decode_base64, payload_b64)
  if not success then
    return nil, "Failed to decode JWT payload"
  end
  
  local success, payload = pcall(cjson.decode, payload_json)
  if not success then
    return nil, "Failed to parse JWT payload JSON"
  end
  
  -- Cache the result
  token_cache[token] = payload
  return payload
end

-- Extract issuer from Bearer token
local function extract_issuer_from_token()
  local auth_header = ngx.var.http_authorization
  if not auth_header then
    return nil
  end
  
  local token = string.match(auth_header, "Bearer%s+(.+)")
  if not token then
    return nil
  end
  
  local payload, err = parse_jwt_payload(token)
  if not payload then
    ngx.log(ngx.ERR, "Failed to parse JWT: ", err)
    return nil
  end
  
  return payload.iss
end

-- Get provider configuration by issuer
local function get_provider_by_issuer(config, issuer)
  if not config.providers then
    return nil
  end
  
  for _, provider in ipairs(config.providers) do
    if provider.issuer == issuer then
      return provider
    end
  end
  
  return nil
end

-- Get provider configuration by header
local function get_provider_by_header(config)
  local header_name = config.provider_header_name or "X-OIDC-Provider"
  local provider_id = ngx.var["http_" .. string.gsub(string.lower(header_name), "%-", "_")]
  
  if not provider_id then
    return nil
  end
  
  return get_provider_by_issuer(config, provider_id)
end

-- Get provider configuration by domain
local function get_provider_by_domain(config)
  if not config.domain_provider_mapping then
    return nil
  end
  
  local host = ngx.var.host
  local issuer = config.domain_provider_mapping[host]
  
  if not issuer then
    return nil
  end
  
  return get_provider_by_issuer(config, issuer)
end

-- Select appropriate provider based on strategy
function M.select_provider(config)
  local strategy = config.provider_selection_strategy or "token_issuer"
  local provider = nil
  
  if strategy == "token_issuer" then
    local issuer = extract_issuer_from_token()
    if issuer then
      provider = get_provider_by_issuer(config, issuer)
    end
  elseif strategy == "header" then
    provider = get_provider_by_header(config)
  elseif strategy == "domain" then
    provider = get_provider_by_domain(config)
  end
  
  -- Fallback to default provider
  if not provider and config.default_provider_issuer then
    provider = get_provider_by_issuer(config, config.default_provider_issuer)
  end
  
  -- Fallback to legacy single provider configuration
  if not provider and config.client_id and config.client_secret and config.discovery then
    provider = {
      issuer = config.discovery,
      client_id = config.client_id,
      client_secret = config.client_secret,
      discovery = config.discovery,
      introspection_endpoint = config.introspection_endpoint,
      timeout = config.timeout,
      introspection_endpoint_auth_method = config.introspection_endpoint_auth_method,
      token_endpoint_auth_method = config.token_endpoint_auth_method,
      scope = config.scope,
      response_type = config.response_type,
      ssl_verify = config.ssl_verify,
      realm = config.realm,
      session_secret = config.session_secret
    }
  end
  
  return provider
end

-- Build OIDC options for a specific provider
function M.get_options(config, ngx)
  local provider = M.select_provider(config)
  
  if not provider then
    ngx.log(ngx.ERR, "No suitable OIDC provider found")
    return nil
  end
  
  ngx.log(ngx.DEBUG, "Selected OIDC provider with issuer: ", provider.issuer)
  
  local opts = {
    client_id = provider.client_id,
    client_secret = provider.client_secret,
    discovery = provider.discovery,
    introspection_endpoint = provider.introspection_endpoint,
    timeout = provider.timeout,
    introspection_endpoint_auth_method = provider.introspection_endpoint_auth_method,
    bearer_only = config.bearer_only,
    realm = provider.realm or config.realm,
    redirect_uri_path = config.redirect_uri_path or "/cb",
    scope = provider.scope or config.scope,
    response_type = provider.response_type or config.response_type,
    ssl_verify = provider.ssl_verify or config.ssl_verify,
    token_endpoint_auth_method = provider.token_endpoint_auth_method or config.token_endpoint_auth_method,
    session_opts = {
      secret = provider.session_secret or config.session_secret or "623q4hR325t36VsCD3g567922IC0073T"
    },
    recovery_page_path = config.recovery_page_path,
    logout_path = "/logout",
    redirect_after_logout_uri = "/",
    refresh_session_interval = 900
  }
  
  -- Store selected provider for use in header injection
  ngx.ctx.selected_oidc_provider = provider
  
  return opts
end

-- Check if request has bearer token
function M.has_bearer_access_token()
  local auth_header = ngx.var.http_authorization
  if auth_header then
    ngx.log(ngx.DEBUG, "Authorization header found")
    local token = string.match(auth_header, "Bearer%s+(.+)")
    if token then
      ngx.log(ngx.DEBUG, "Bearer token found")
      return token
    end
  end
  return false
end

-- Inject user info into headers
function M.injectUser(user)
  local tmp_user = user
  tmp_user.id = user.sub
  tmp_user.username = user.preferred_username
  ngx.req.set_header("X-Userinfo", cjson.encode(tmp_user))
end

-- Inject access token into headers
function M.injectAccessToken(access_token)
  ngx.req.set_header("X-Access-Token", access_token)
end

-- Inject ID token into headers
function M.injectIDToken(id_token)
  ngx.req.set_header("X-Id-Token", id_token)
end

-- Inject custom headers based on provider configuration
function M.injectCustomHeaders(user_info)
  local provider = ngx.ctx.selected_oidc_provider
  if not provider or not provider.header_names or not provider.header_claims then
    return
  end
  
  for i, header_name in ipairs(provider.header_names) do
    local claim_name = provider.header_claims[i]
    if claim_name and user_info[claim_name] then
      ngx.req.set_header(header_name, tostring(user_info[claim_name]))
    end
  end
end

-- Exit with error
function M.exit(httpStatusCode, message, ngxCode)
  ngx.status = httpStatusCode
  ngx.say(message)
  ngx.exit(ngxCode)
end

return M