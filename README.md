# OnSecurity MCP

A Model Context Protocol (MCP) connector for the OnSecurity API that allows Claude to query rounds, findings, and notifications.

## Installation

```bash
git clone https://github.com/onsecurity/onsecurity-mcp-server.git
cd onsecurity-mcp-server
npm install
npm run build
```

## Configuration

The server supports two transport modes:
1. **Stdio Transport** (default) - For use with Claude Desktop
2. **HTTP Transport** - For use with web-based clients or when multiple connections are needed

### Environment Variables

Copy the example environment file and edit it:

```bash
cp env.example .env
```

Edit the `.env` file with your API credentials and server settings:

```
# OnSecurity API Configuration
ONSECURITY_API_TOKEN=your_api_token
ONSECURITY_CLIENT_ID=your_client_id
ONSECURITY_API_BASE=https://app.onsecurity.io/api/v2

# MCP Server Configuration
# Set to 'http' to use the Streamable HTTP transport, otherwise leave empty for stdio
MCP_TRANSPORT=http

# HTTP Server Configuration (only used when MCP_TRANSPORT=http)
PORT=3000
HOST=127.0.0.1
ALLOWED_ORIGINS=http://localhost:3000,https://app.example.com
```

### Claude Desktop Configuration (Stdio Transport)

To use this MCP server with Claude Desktop, you need to add an entry to your Claude Desktop configuration file.

Add the following to your configuration file (adjust the paths as needed) and choose UAT or Prod:

```json
{
  "mcpServers": {
    "onsec-mcp": {
      "command": "node",
      "args": [
        "/path/to/onsecurity-mcp-server/build/index.js"
      ],
      "env": {
        "ONSECURITY_API_TOKEN": "your_api_token",
        "ONSECURITY_API_BASE": "https://app.onsecurity.io/api/v2"
      }
    }
  }
}
```

After adding this configuration, restart Claude Desktop, and you'll be able to access the OnSecurity tools through Claude.

### HTTP Transport Configuration

To use the server with HTTP transport, set `MCP_TRANSPORT=http` in your `.env` file and run:

```bash
node build/index.js
```

This will start the server at `http://127.0.0.1:3000/mcp` (or the HOST/PORT you specified in the environment variables).

For security reasons, the server binds to localhost by default and validates origins for CORS. If you need to allow external connections:

1. Set `HOST=0.0.0.0` (not recommended for production without proper security measures)
2. Add the allowed origins to `ALLOWED_ORIGINS` as a comma-separated list

## Usage

Once configured, Claude will have access to the following tools:

- `get-rounds` - Get information about security assessment rounds
- `get-findings` - Get findings from security assessments
- `get-notifications` - Get notifications and updates
- `get-prerequisites` - Get prerequisites for security assessments

### Example Questions
- Give me a summary of my most recent pentest/scan.
- Show me trends across my pentests as a graph.
- What can I address to make the most impact most quickly on my most recent pentest?
- I would like summaries for different types of stakeholders on the state of our recent pentest engagemenets - eg high level, technical, managerial etc
- Do I need to action anything to prevent test getting held up?
- Are there any new findings?

*Note: It is useful sometimes to configure Claude to "Extended thinking" for some questions.*
