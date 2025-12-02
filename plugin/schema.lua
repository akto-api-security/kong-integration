local typedefs = require "kong.db.schema.typedefs"

return {
  name = "akto-mcp-endpoint-shield",
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          -- Guardrail service URL
          { service_url = { type = "string", required = true, default = "http://localhost:9091" } },

          -- Mode: "async" (non-blocking) or "blocked" (blocking)
          { mode = { type = "string", required = true, default = "async", one_of = { "async", "blocked" } } },

          -- Timeout in milliseconds for guardrail service and upstream calls
          { timeout = { type = "number", required = false, default = 30000 } },
        },
      },
    },
  },
}
