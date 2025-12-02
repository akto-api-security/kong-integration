local http = require "resty.http"
local cjson = require "cjson.safe"

local AktoMCPEndpointShieldHandler = {
  PRIORITY = 1000,
  VERSION = "1.0.0",
}

-- Store request/response bodies in ngx.ctx for access across phases
local function store_request_body()
  if not ngx.ctx.mcp_request_body then
    local body = kong.request.get_raw_body()
    ngx.ctx.mcp_request_body = body or ""
  end
  return ngx.ctx.mcp_request_body
end

local function store_response_body()
  -- Initialize response body chunks table if not exists
  if not ngx.ctx.mcp_response_chunks then
    ngx.ctx.mcp_response_chunks = {}
    ngx.ctx.mcp_response_body_complete = false
  end

  -- Get current chunk from body_filter phase
  local chunk = ngx.arg[1]
  if chunk and chunk ~= "" then
    table.insert(ngx.ctx.mcp_response_chunks, chunk)
  end

  -- Check if this is the last chunk (eof marker)
  local eof = ngx.arg[2]
  if eof then
    -- Concatenate all chunks into final body
    ngx.ctx.mcp_response_body = table.concat(ngx.ctx.mcp_response_chunks)
    ngx.ctx.mcp_response_body_complete = true
  end

  return ngx.ctx.mcp_response_body or ""
end

-- Helper function to make HTTP requests to the Go service
local function call_go_service(service_url, endpoint, payload, timeout_ms)
  local httpc = http.new()

  -- Parse service URL to get host and port
  local host, port = service_url:match("^https?://([^:]+):(%d+)")
  if not host or not port then
    host = service_url:match("^https?://([^:/]+)")
    port = service_url:match("^https://") and "443" or "80"
  end

  -- Use provided timeout or default to 30 seconds
  local timeout = timeout_ms or 30000
  local connect_timeout = math.floor(timeout / 3)
  local send_timeout = math.floor(timeout / 3)
  local read_timeout = timeout - connect_timeout - send_timeout

  httpc:set_timeouts(connect_timeout, send_timeout, read_timeout)

  -- Connect explicitly
  local ok, err = httpc:connect(host, tonumber(port))
  if not ok then
    return nil, "Failed to connect to Go service at " .. host .. ":" .. port .. ": " .. (err or "unknown error")
  end

  local body = cjson.encode(payload)

  -- Make the request
  local res, err = httpc:request({
    method = "POST",
    path = endpoint,
    body = body,
    headers = {
      ["Content-Type"] = "application/json",
      ["Content-Length"] = tostring(#body),
      ["Host"] = host,
      ["Connection"] = "close",
    },
  })

  if not res then
    httpc:close()
    return nil, "Failed to send request to Go service: " .. (err or "unknown error")
  end

  -- Read the body
  local response_body, err = res:read_body()
  local status = res.status

  -- Close the connection
  httpc:close()

  if not response_body then
    return nil, "Failed to read response body: " .. (err or "unknown error")
  end

  if status ~= 200 then
    return nil, "Go service returned status " .. status .. ": " .. response_body
  end

  local result, decode_err = cjson.decode(response_body)
  if not result then
    return nil, "Failed to decode Go service response: " .. (decode_err or "unknown error")
  end

  return result, nil
end

-- Access phase: Process incoming requests
function AktoMCPEndpointShieldHandler:access(conf)
  -- Enable request body buffering
  kong.service.request.enable_buffering()

  -- Store request body for later use
  store_request_body()

  -- For blocked mode, proxy entire request/response through guardrail service
  if conf.mode == "blocked" then
    self:process_blocked_mode_proxy(conf)
  end
  -- For async mode, we'll process everything in log phase (non-blocking)
end

-- Process BLOCKED mode by manually proxying and validating both request and response
function AktoMCPEndpointShieldHandler:process_blocked_mode_proxy(conf)
  local request_body = ngx.ctx.mcp_request_body or ""
  local request_headers = kong.request.get_headers()
  local request_method = kong.request.get_method()
  local request_path = kong.request.get_path()
  local query_params = kong.request.get_query()

  -- Step 1: Validate request first
  local request_payload = {
    request_body = request_body,
    request_headers = request_headers,
    query_params = query_params,
    ip = kong.client.get_forwarded_ip() or kong.client.get_ip(),
    method = request_method,
    endpoint = request_path,
    mode = conf.mode,
  }

  kong.log.info("[akto-mcp-endpoint-shield] [BLOCKED MODE] Validating request")

  local request_result, err = call_go_service(
    conf.service_url,
    "/process/request",
    request_payload,
    conf.timeout
  )

  if err then
    kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED MODE] Error validating request: ", err)
    -- Fail-open: Continue with normal proxy
    return
  end

  -- If request is blocked, stop here
  if request_result and request_result.is_blocked then
    kong.log.warn("[akto-mcp-endpoint-shield] [BLOCKED MODE] Request BLOCKED by guardrail")

    local blocked_response = request_result.blocked_response or {
      error = "Request blocked by guardrails",
      message = "Your request was blocked due to security policies"
    }

    return kong.response.exit(403, blocked_response)
  end

  -- If request should be modified, update it
  local forward_body = request_body
  if request_result and request_result.modified_payload and request_result.modified_payload ~= "" then
    kong.log.info("[akto-mcp-endpoint-shield] [BLOCKED MODE] Request modified by guardrail")
    forward_body = request_result.modified_payload
    kong.service.request.set_raw_body(forward_body)
  end

  kong.log.info("[akto-mcp-endpoint-shield] [BLOCKED MODE] Request validated")

  -- Step 2: Manually call upstream service to get response
  kong.log.info("[akto-mcp-endpoint-shield] [BLOCKED MODE] Calling upstream service")

  local httpc = http.new()
  local upstream_timeout = conf.timeout or 30000
  httpc:set_timeouts(upstream_timeout, upstream_timeout, upstream_timeout)

  -- Get upstream service details from Kong
  local service = kong.router.get_service()
  local upstream_host = service and service.host or "host.docker.internal"
  local upstream_port = service and service.port or 3000

  local ok, err = httpc:connect(upstream_host, upstream_port)
  if not ok then
    kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED MODE] Failed to connect to upstream: ", err)
    -- Fail-open: continue with normal proxy
    return
  end

  local res, err = httpc:request({
    method = request_method,
    path = request_path,
    body = forward_body,
    headers = request_headers,
  })

  if not res then
    httpc:close()
    kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED MODE] Failed to call upstream: ", err)
    -- Fail-open: continue with normal proxy
    return
  end

  local response_body, err = res:read_body()
  local response_status = res.status
  local response_headers = res.headers

  httpc:close()

  if not response_body then
    kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED MODE] Failed to read upstream response: ", err)
    -- Fail-open: continue with normal proxy
    return
  end

  kong.log.info("[akto-mcp-endpoint-shield] [BLOCKED MODE] Got upstream response, validating")

  -- Step 3: Validate response
  local response_payload = {
    request_body = forward_body,
    response_body = response_body,
    request_headers = request_headers,
    response_headers = response_headers,
    query_params = query_params,
    status_code = response_status,
    ip = kong.client.get_forwarded_ip() or kong.client.get_ip(),
    method = request_method,
    endpoint = request_path,
    mode = conf.mode,
  }

  local response_result, err = call_go_service(
    conf.service_url,
    "/process/response",
    response_payload,
    conf.timeout
  )

  if err then
    kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED MODE] Error validating response: ", err)
    -- Fail-open: return original response
    return kong.response.exit(response_status, response_body, response_headers)
  end

  -- Check if response should be blocked
  if response_result and response_result.is_blocked then
    kong.log.warn("[akto-mcp-endpoint-shield] [BLOCKED MODE] Response BLOCKED by guardrail")

    local blocked_response = response_result.blocked_response or {
      error = "Response blocked by guardrails",
      message = "The response was blocked due to security policies"
    }

    return kong.response.exit(403, blocked_response)
  end

  -- Check if response should be modified
  if response_result and response_result.modified_payload and response_result.modified_payload ~= "" then
    kong.log.info("[akto-mcp-endpoint-shield] [BLOCKED MODE] Response modified by guardrail")
    return kong.response.exit(response_status, response_result.modified_payload, response_headers)
  end

  kong.log.info("[akto-mcp-endpoint-shield] [BLOCKED MODE] Response is clean, sending to client")
  -- Return original response
  return kong.response.exit(response_status, response_body, response_headers)
end

-- Header filter phase: Enable response buffering for async mode
function AktoMCPEndpointShieldHandler:header_filter(conf)
  -- Only enable buffering for async mode (blocked mode handles everything in access phase)
  if conf.mode == "async" then
    kong.response.get_source() -- This triggers buffering
  end
end

-- Body filter phase: Store response body for async mode
function AktoMCPEndpointShieldHandler:body_filter(conf)
  -- Only capture response for async mode (blocked mode already handled in access phase)
  if conf.mode == "async" then
    store_response_body()
  end
end

-- Log phase: Process in ASYNC mode only (blocked mode handled in access phase)
function AktoMCPEndpointShieldHandler:log(conf)
  -- Only process in async mode
  if conf.mode ~= "async" then
    return
  end

  -- Force ERROR level logging so it shows up
  ngx.log(ngx.ERR, "========== MCP-SHIELD LOG PHASE START ==========")

  -- Get stored bodies from context
  local request_body = ngx.ctx.mcp_request_body or ""
  local response_body = ngx.ctx.mcp_response_body or ""

  -- Log what we captured with ERROR level
  ngx.log(ngx.ERR, "[MCP-SHIELD] Request body length: ", #request_body)
  ngx.log(ngx.ERR, "[MCP-SHIELD] Response body length: ", #response_body)
  ngx.log(ngx.ERR, "[MCP-SHIELD] Response body complete: ", tostring(ngx.ctx.mcp_response_body_complete))

  if #request_body > 0 then
    ngx.log(ngx.ERR, "[MCP-SHIELD] Request body: ", string.sub(request_body, 1, 200))
  else
    ngx.log(ngx.ERR, "[MCP-SHIELD] WARNING: Request body is EMPTY!")
  end

  if #response_body > 0 then
    ngx.log(ngx.ERR, "[MCP-SHIELD] Response body: ", string.sub(response_body, 1, 200))
  else
    ngx.log(ngx.ERR, "[MCP-SHIELD] WARNING: Response body is EMPTY!")
  end

  -- IMPORTANT: Capture all data BEFORE the timer
  -- Kong PDK functions are NOT available inside ngx.timer.at
  local request_headers = kong.request.get_headers()
  local response_headers = kong.response.get_headers()
  local query_params = kong.request.get_query()
  local client_ip = kong.client.get_forwarded_ip() or kong.client.get_ip()
  local request_method = kong.request.get_method()
  local request_path = kong.request.get_path()
  local response_status = kong.response.get_status()
  local service_url = conf.service_url
  local timeout_ms = conf.timeout

  -- Log captured headers with ERROR level
  local req_hdr_count = 0
  local resp_hdr_count = 0
  if request_headers then
    for k, v in pairs(request_headers) do
      req_hdr_count = req_hdr_count + 1
    end
  end
  if response_headers then
    for k, v in pairs(response_headers) do
      resp_hdr_count = resp_hdr_count + 1
    end
  end

  ngx.log(ngx.ERR, "[MCP-SHIELD] Request headers count: ", req_hdr_count)
  ngx.log(ngx.ERR, "[MCP-SHIELD] Response headers count: ", resp_hdr_count)
  ngx.log(ngx.ERR, "[MCP-SHIELD] Response status: ", response_status)
  ngx.log(ngx.ERR, "[MCP-SHIELD] Request path: ", request_path)
  ngx.log(ngx.ERR, "[MCP-SHIELD] Request method: ", request_method)

  local mode = conf.mode

  -- Process in background using ngx.timer.at
  local ok, err = ngx.timer.at(0, function(premature)
    if premature then
      ngx.log(ngx.ERR, "[akto-mcp-endpoint-shield] [", string.upper(mode), " MODE] Timer premature exit")
      return
    end

    ngx.log(ngx.INFO, "[akto-mcp-endpoint-shield] [", string.upper(mode), " MODE] Background timer executing")

    -- ASYNC MODE: Process both request and response together
    local both_payload = {
      request_body = request_body,
      response_body = response_body,
      request_headers = request_headers,
      response_headers = response_headers,
      query_params = query_params,
      status_code = response_status,
      ip = client_ip,
      method = request_method,
      endpoint = request_path,
      mode = "async",
    }

    ngx.log(ngx.INFO, "[akto-mcp-endpoint-shield] [ASYNC MODE] Calling /process/both")
    local result, err = call_go_service(
      service_url,
      "/process/both",
      both_payload,
      timeout_ms
    )

    if err then
      ngx.log(ngx.ERR, "[akto-mcp-endpoint-shield] [ASYNC MODE] Processing error: ", err)
    else
      ngx.log(ngx.INFO, "[akto-mcp-endpoint-shield] [ASYNC MODE] Processing completed")
      ngx.log(ngx.INFO, "[akto-mcp-endpoint-shield] [ASYNC MODE] Request result: is_blocked=",
        tostring(result.request_result and result.request_result.is_blocked))
      ngx.log(ngx.INFO, "[akto-mcp-endpoint-shield] [ASYNC MODE] Response result: is_blocked=",
        tostring(result.response_result and result.response_result.is_blocked))
      ngx.log(ngx.INFO, "[akto-mcp-endpoint-shield] [ASYNC MODE] Total time: ", tostring(result.total_time_ms), "ms")
    end

    ngx.log(ngx.INFO, "[akto-mcp-endpoint-shield] [", string.upper(mode), " MODE] Background processing completed")
  end)

  if not ok then
    kong.log.err("[akto-mcp-endpoint-shield] [", string.upper(mode), " MODE] Failed to create background timer: ", err)
  else
    kong.log.info("[akto-mcp-endpoint-shield] [", string.upper(mode), " MODE] Background timer created successfully")
  end
end

return AktoMCPEndpointShieldHandler
