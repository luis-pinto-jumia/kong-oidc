local BasePlugin = require "kong.plugins.base_plugin"
local OidcHandler = BasePlugin:extend()
local utils = require("kong.plugins.oidc.utils")
local filter = require("kong.plugins.oidc.filter")
local session = require("kong.plugins.oidc.session")

OidcHandler.PRIORITY = 1000

function OidcHandler:new()
  OidcHandler.super.new(self, "oidc")
end

function OidcHandler:access(config)
  OidcHandler.super.access(self)
  
  -- Validate configuration
  if not self:validate_config(config) then
    utils.exit(500, "Invalid OIDC configuration", ngx.HTTP_INTERNAL_SERVER_ERROR)
    return
  end
  
  local oidcConfig = utils.get_options(config, ngx)
  
  if not oidcConfig then
    ngx.log(ngx.ERR, "Failed to select OIDC provider")
    utils.exit(500, "OIDC provider selection failed", ngx.HTTP_INTERNAL_SERVER_ERROR)
    return
  end

  if filter.shouldProcessRequest(oidcConfig) then
    session.configure(config)
    self:handle(oidcConfig)
  else
    ngx.log(ngx.DEBUG, "OidcHandler ignoring request, path: " .. ngx.var.request_uri)
  end

  ngx.log(ngx.DEBUG, "OidcHandler done")
end

function OidcHandler:validate_config(config)
  -- Check if we have either legacy config or providers array
  local has_legacy = config.client_id and config.client_secret and config.discovery
  local has_providers = config.providers and #config.providers > 0
  
  if not has_legacy and not has_providers then
    ngx.log(ngx.ERR, "No OIDC configuration found. Provide either legacy config or providers array.")
    return false
  end
  
  -- Validate providers array if present
  if has_providers then
    for i, provider in ipairs(config.providers) do
      if not provider.issuer or not provider.client_id or not provider.client_secret or not provider.discovery then
        ngx.log(ngx.ERR, "Provider " .. i .. " missing required fields")
        return false
      end
    end
  end
  
  return true
end

function OidcHandler:handle(oidcConfig)
  local response
  
  -- Try introspection first if endpoint is configured
  if oidcConfig.introspection_endpoint then
    response = self:introspect(oidcConfig)
    if response then
      utils.injectUser(response)
      utils.injectCustomHeaders(response)
      return
    end
  end

  -- Try OIDC authentication flow
  if response == nil then
    response = self:make_oidc(oidcConfig)
    if response then
      if response.user then
        utils.injectUser(response.user)
        utils.injectCustomHeaders(response.user)
      end
      if response.access_token then
        utils.injectAccessToken(response.access_token)
      end
      if response.id_token then
        utils.injectIDToken(response.id_token)
      end
    end
  end
end

function OidcHandler:introspect(oidcConfig)
  if utils.has_bearer_access_token() or oidcConfig.bearer_only == "yes" then
    local res, err = require("resty.openidc").introspect(oidcConfig)
    if err then
      ngx.log(ngx.ERR, "Introspection failed: ", err)
      if oidcConfig.bearer_only == "yes" then
        ngx.header["WWW-Authenticate"] = 'Bearer realm="' .. oidcConfig.realm .. '",error="' .. err .. '"'
        utils.exit(ngx.HTTP_UNAUTHORIZED, err, ngx.HTTP_UNAUTHORIZED)
      end
      return nil
    end
    ngx.log(ngx.DEBUG, "OidcHandler introspect succeeded, requested path: " .. ngx.var.request_uri)
    return res
  end
  return nil
end

function OidcHandler:make_oidc(oidcConfig)
  ngx.log(ngx.DEBUG, "OidcHandler calling authenticate, requested path: " .. ngx.var.request_uri)
  local res, err = require("resty.openidc").authenticate(oidcConfig)
  if err then
    ngx.log(ngx.ERR, "OIDC authentication failed: ", err)
    if oidcConfig.recovery_page_path then
      ngx.log(ngx.DEBUG, "Entering recovery page: " .. oidcConfig.recovery_page_path)
      ngx.redirect(oidcConfig.recovery_page_path)
    end
    utils.exit(500, err, ngx.HTTP_INTERNAL_SERVER_ERROR)
  end
  return res
end

return OidcHandler