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
  kong.log.err("[akto-mcp-endpoint-shield] ========== ACCESS PHASE START ==========")
  kong.log.err("[akto-mcp-endpoint-shield] Mode: ", conf.mode)
  kong.log.err("[akto-mcp-endpoint-shield] Service URL: ", conf.service_url)
  kong.log.err("[akto-mcp-endpoint-shield] Timeout: ", conf.timeout, "ms")

  -- Enable request body buffering
  kong.service.request.enable_buffering()
  kong.log.err("[akto-mcp-endpoint-shield] Request body buffering enabled")

  -- Store request body for later use
  local req_body = store_request_body()
  kong.log.err("[akto-mcp-endpoint-shield] Request body stored, length: ", #req_body)

  -- For blocked mode, proxy entire request/response through guardrail service
  if conf.mode == "blocked" then
    kong.log.err("[akto-mcp-endpoint-shield] Entering BLOCKED mode processing")
    self:process_blocked_mode_proxy(conf)
  else
    kong.log.err("[akto-mcp-endpoint-shield] ASYNC mode - will process in log phase")
  end

  kong.log.err("[akto-mcp-endpoint-shield] ========== ACCESS PHASE END ==========")
end

-- Process BLOCKED mode by manually proxying and validating both request and response
function AktoMCPEndpointShieldHandler:process_blocked_mode_proxy(conf)
  kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] ========== BLOCKED MODE START ==========")

  local request_body = ngx.ctx.mcp_request_body or ""
  local request_headers = kong.request.get_headers()
  local request_method = kong.request.get_method()
  local request_path = kong.request.get_path()
  local query_params = kong.request.get_query()

  kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] Request details:")
  kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED]   Method: ", request_method)
  kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED]   Path: ", request_path)
  kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED]   Body length: ", #request_body)
  kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED]   Query params: ", cjson.encode(query_params or {}))

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

  kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] Step 1: Validating request with guardrail service")
  kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] Request payload details:")
  kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED]   request_body length: ", #request_body)
  kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED]   request_body preview: ", string.sub(request_body, 1, 200))
  kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED]   query_params: ", cjson.encode(query_params or {}))
  kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED]   ip: ", request_payload.ip)
  kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED]   method: ", request_payload.method)
  kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED]   endpoint: ", request_payload.endpoint)
  kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED]   mode: ", request_payload.mode)

  -- Log request headers (first few)
  local header_count = 0
  for k, v in pairs(request_headers) do
    if header_count < 5 then
      kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED]   header[", k, "]: ", tostring(v))
      header_count = header_count + 1
    end
  end
  if header_count >= 5 then
    kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED]   ... (more headers not shown)")
  end

  kong.log.info("[akto-mcp-endpoint-shield] [BLOCKED MODE] Validating request")

  local request_result, err = call_go_service(
    conf.service_url,
    "/process/request",
    request_payload,
    conf.timeout
  )

  if err then
    kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] ERROR: Request validation failed")
    kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] Error details: ", err)
    kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] Fail-open: Continuing with normal proxy")
    kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED MODE] Error validating request: ", err)
    kong.log.err(err)
    -- Fail-open: Continue with normal proxy
    return
  end

  kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] Request validation response received")
  kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED]   is_blocked: ", tostring(request_result and request_result.is_blocked))

  -- If request is blocked, stop here
  if request_result and request_result.is_blocked then
    kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] *** REQUEST BLOCKED BY GUARDRAIL ***")
    kong.log.warn("[akto-mcp-endpoint-shield] [BLOCKED MODE] Request BLOCKED by guardrail")

    local blocked_response = request_result.blocked_response or {
      error = "Request blocked by guardrails",
      message = "Your request was blocked due to security policies"
    }

    kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] Returning 403 to client")
    return kong.response.exit(403, blocked_response)
  end

  -- If request should be modified, update it
  local forward_body = request_body
  if request_result and request_result.modified_payload and request_result.modified_payload ~= "" then
    kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] Request MODIFIED by guardrail")
    kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED]   Original length: ", #request_body)
    kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED]   Modified length: ", #request_result.modified_payload)
    kong.log.info("[akto-mcp-endpoint-shield] [BLOCKED MODE] Request modified by guardrail")
    forward_body = request_result.modified_payload
    kong.service.request.set_raw_body(forward_body)
  end

  kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] Request validation complete - ALLOWED")
  kong.log.info("[akto-mcp-endpoint-shield] [BLOCKED MODE] Request validated")

  -- Step 2: Manually call upstream service to get response
  kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] Step 2: Calling upstream service")
  kong.log.info("[akto-mcp-endpoint-shield] [BLOCKED MODE] Calling upstream service")

  local httpc = http.new()
  local upstream_timeout = conf.timeout or 30000
  httpc:set_timeouts(upstream_timeout, upstream_timeout, upstream_timeout)

  -- Get upstream service details from Kong
  local service = kong.router.get_service()
  local upstream_host = service and service.host or "host.docker.internal"
  local upstream_port = service and service.port or 3000

  kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] Upstream details:")
  kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED]   Host: ", upstream_host)
  kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED]   Port: ", upstream_port)
  kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED]   Timeout: ", upstream_timeout, "ms")

  local ok, err = httpc:connect(upstream_host, upstream_port)
  if not ok then
    kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] ERROR: Failed to connect to upstream")
    kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] Error details: ", err)
    kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] Fail-open: Continuing with normal proxy")
    kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED MODE] Failed to connect to upstream: ", err)
    -- Fail-open: continue with normal proxy
    return
  end

  kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] Connected to upstream, sending request")

  local res, err = httpc:request({
    method = request_method,
    path = request_path,
    body = forward_body,
    headers = request_headers,
  })

  if not res then
    httpc:close()
    kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] ERROR: Failed to call upstream")
    kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] Error details: ", err)
    kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] Fail-open: Continuing with normal proxy")
    kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED MODE] Failed to call upstream: ", err)
    -- Fail-open: continue with normal proxy
    return
  end

  kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] Upstream responded with status: ", res.status)

  local response_body, err = res:read_body()
  local response_status = res.status
  local response_headers = res.headers

  httpc:close()

  if not response_body then
    kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] ERROR: Failed to read upstream response")
    kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] Error details: ", err)
    kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] Fail-open: Continuing with normal proxy")
    kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED MODE] Failed to read upstream response: ", err)
    -- Fail-open: continue with normal proxy
    return
  end

  kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] Upstream response received, body length: ", #response_body)
  kong.log.info("[akto-mcp-endpoint-shield] [BLOCKED MODE] Got upstream response, validating")

  -- Step 3: Validate response
  kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] Step 3: Validating response with guardrail service")

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

  kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] Response payload details:")
  kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED]   response_body length: ", #response_body)
  kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED]   response_body preview: ", string.sub(response_body, 1, 200))
  kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED]   status_code: ", response_status)

  local response_result, err = call_go_service(
    conf.service_url,
    "/process/response",
    response_payload,
    conf.timeout
  )

  if err then
    kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] ERROR: Response validation failed")
    kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] Error details: ", err)
    kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] Fail-open: Returning original response")
    kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED MODE] Error validating response: ", err)
    kong.log.err(err)
    -- Fail-open: return original response
    return kong.response.exit(response_status, response_body, response_headers)
  end

  kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] Response validation response received")
  kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED]   is_blocked: ", tostring(response_result and response_result.is_blocked))

  -- Check if response should be blocked
  if response_result and response_result.is_blocked then
    kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] *** RESPONSE BLOCKED BY GUARDRAIL ***")
    kong.log.warn("[akto-mcp-endpoint-shield] [BLOCKED MODE] Response BLOCKED by guardrail")

    local blocked_response = response_result.blocked_response or {
      error = "Response blocked by guardrails",
      message = "The response was blocked due to security policies"
    }

    kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] Returning 403 to client")
    return kong.response.exit(403, blocked_response)
  end

  -- Check if response should be modified
  if response_result and response_result.modified_payload and response_result.modified_payload ~= "" then
    kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] Response MODIFIED by guardrail")
    kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED]   Original length: ", #response_body)
    kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED]   Modified length: ", #response_result.modified_payload)
    kong.log.info("[akto-mcp-endpoint-shield] [BLOCKED MODE] Response modified by guardrail")
    return kong.response.exit(response_status, response_result.modified_payload, response_headers)
  end

  kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] Response validation complete - ALLOWED")
  kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] Sending original response to client")
  kong.log.info("[akto-mcp-endpoint-shield] [BLOCKED MODE] Response is clean, sending to client")
  kong.log.err("[akto-mcp-endpoint-shield] [BLOCKED] ========== BLOCKED MODE END ==========")
  -- Return original response
  return kong.response.exit(response_status, response_body, response_headers)
end

-- Header filter phase: Enable response buffering for async mode
function AktoMCPEndpointShieldHandler:header_filter(conf)
  kong.log.err("[akto-mcp-endpoint-shield] ========== HEADER_FILTER PHASE ==========")
  kong.log.err("[akto-mcp-endpoint-shield] Mode: ", conf.mode)

  -- Only enable buffering for async mode (blocked mode handles everything in access phase)
  if conf.mode == "async" then
    kong.log.err("[akto-mcp-endpoint-shield] [ASYNC] Enabling response buffering")
    kong.response.get_source() -- This triggers buffering
  else
    kong.log.err("[akto-mcp-endpoint-shield] Skipping (blocked mode handles in access phase)")
  end
end

-- Body filter phase: Store response body for async mode
function AktoMCPEndpointShieldHandler:body_filter(conf)
  -- Only capture response for async mode (blocked mode already handled in access phase)
  if conf.mode == "async" then
    local chunk = ngx.arg[1]
    local eof = ngx.arg[2]

    if chunk and chunk ~= "" then
      kong.log.err("[akto-mcp-endpoint-shield] [ASYNC] Body filter: Received chunk of size ", #chunk)
    end

    if eof then
      kong.log.err("[akto-mcp-endpoint-shield] [ASYNC] Body filter: EOF reached, response complete")
    end

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
  kong.log.err("========== MCP-SHIELD LOG PHASE START ==========")

  -- Get stored bodies from context
  local request_body = ngx.ctx.mcp_request_body or ""
  local response_body = ngx.ctx.mcp_response_body or ""

  -- Log what we captured with ERROR level
  kong.log.err("[akto-mcp-endpoint-shield] Request body length: ", #request_body)
  kong.log.err("[akto-mcp-endpoint-shield] Response body length: ", #response_body)
  kong.log.err("[akto-mcp-endpoint-shield] Response body complete: ", tostring(ngx.ctx.mcp_response_body_complete))

  if #request_body > 0 then
    kong.log.err("[akto-mcp-endpoint-shield] Request body: ", string.sub(request_body, 1, 200))
  else
    kong.log.err("[akto-mcp-endpoint-shield] WARNING: Request body is EMPTY!")
  end

  if #response_body > 0 then
    kong.log.err("[akto-mcp-endpoint-shield] Response body: ", string.sub(response_body, 1, 200))
  else
    kong.log.err("[akto-mcp-endpoint-shield] WARNING: Response body is EMPTY!")
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

  kong.log.err("[akto-mcp-endpoint-shield] [ASYNC] Request details captured:")
  kong.log.err("[akto-mcp-endpoint-shield] [ASYNC]   Request headers count: ", req_hdr_count)
  kong.log.err("[akto-mcp-endpoint-shield] [ASYNC]   Response headers count: ", resp_hdr_count)
  kong.log.err("[akto-mcp-endpoint-shield] [ASYNC]   Response status: ", response_status)
  kong.log.err("[akto-mcp-endpoint-shield] [ASYNC]   Request path: ", request_path)
  kong.log.err("[akto-mcp-endpoint-shield] [ASYNC]   Request method: ", request_method)
  kong.log.err("[akto-mcp-endpoint-shield] [ASYNC]   Client IP: ", client_ip)
  kong.log.err("[akto-mcp-endpoint-shield] [ASYNC]   Query params: ", cjson.encode(query_params or {}))
  kong.log.err("[akto-mcp-endpoint-shield] [ASYNC]   Service URL: ", service_url)
  kong.log.err("[akto-mcp-endpoint-shield] [ASYNC]   Timeout: ", timeout_ms, "ms")

  local mode = conf.mode

  -- Process in background using ngx.timer.at
  kong.log.err("[akto-mcp-endpoint-shield] [ASYNC] Creating background timer for processing")

  local ok, err = ngx.timer.at(0, function(premature)
    if premature then
      kong.log.err("[akto-mcp-endpoint-shield] [ASYNC] Timer premature exit")
      kong.log.err("[akto-mcp-endpoint-shield] [", string.upper(mode), " MODE] Timer premature exit")
      return
    end

    kong.log.err("[akto-mcp-endpoint-shield] [ASYNC] ========== BACKGROUND TIMER EXECUTING ==========")
    kong.log.err("[akto-mcp-endpoint-shield] [", string.upper(mode), " MODE] Background timer executing")

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

    kong.log.err("[akto-mcp-endpoint-shield] [ASYNC] Payload prepared:")
    kong.log.err("[akto-mcp-endpoint-shield] [ASYNC]   request_body length: ", #request_body)
    kong.log.err("[akto-mcp-endpoint-shield] [ASYNC]   response_body length: ", #response_body)
    kong.log.err("[akto-mcp-endpoint-shield] [ASYNC]   status_code: ", response_status)
    kong.log.err("[akto-mcp-endpoint-shield] [ASYNC]   endpoint: ", request_path)
    kong.log.err("[akto-mcp-endpoint-shield] [ASYNC] Calling /process/both endpoint...")

    kong.log.err("[akto-mcp-endpoint-shield] [ASYNC MODE] Calling /process/both")
    local result, err = call_go_service(
      service_url,
      "/process/both",
      both_payload,
      timeout_ms
    )

    if err then
      kong.log.err("[akto-mcp-endpoint-shield] [ASYNC] ERROR: Processing failed")
      kong.log.err("[akto-mcp-endpoint-shield] [ASYNC] Error details: ", err)
      kong.log.err("[akto-mcp-endpoint-shield] [ASYNC MODE] Processing error: ", err)
    else
      kong.log.err("[akto-mcp-endpoint-shield] [ASYNC] Processing completed successfully")
      kong.log.err("[akto-mcp-endpoint-shield] [ASYNC MODE] Processing completed")

      if result.request_result then
        kong.log.err("[akto-mcp-endpoint-shield] [ASYNC] Request result: is_blocked=", tostring(result.request_result.is_blocked))
        kong.log.err("[akto-mcp-endpoint-shield] [ASYNC MODE] Request result: is_blocked=",
          tostring(result.request_result.is_blocked))
      end

      if result.response_result then
        kong.log.err("[akto-mcp-endpoint-shield] [ASYNC] Response result: is_blocked=", tostring(result.response_result.is_blocked))
        kong.log.err("[akto-mcp-endpoint-shield] [ASYNC MODE] Response result: is_blocked=",
          tostring(result.response_result.is_blocked))
      end

      if result.total_time_ms then
        kong.log.err("[akto-mcp-endpoint-shield] [ASYNC] Total processing time: ", tostring(result.total_time_ms), "ms")
        kong.log.err("[akto-mcp-endpoint-shield] [ASYNC MODE] Total time: ", tostring(result.total_time_ms), "ms")
      end
    end

    kong.log.err("[akto-mcp-endpoint-shield] [ASYNC] ========== BACKGROUND TIMER END ==========")
    kong.log.err("[akto-mcp-endpoint-shield] [", string.upper(mode), " MODE] Background processing completed")
  end)

  if not ok then
    kong.log.err("[akto-mcp-endpoint-shield] [ASYNC] ERROR: Failed to create background timer")
    kong.log.err("[akto-mcp-endpoint-shield] [ASYNC] Error details: ", err)
    kong.log.err("[akto-mcp-endpoint-shield] [", string.upper(mode), " MODE] Failed to create background timer: ", err)
  else
    kong.log.err("[akto-mcp-endpoint-shield] [ASYNC] Background timer created successfully")
    kong.log.err("[akto-mcp-endpoint-shield] [", string.upper(mode), " MODE] Background timer created successfully")
  end

  kong.log.err("[akto-mcp-endpoint-shield] ========== LOG PHASE END ==========")
end

return AktoMCPEndpointShieldHandler
