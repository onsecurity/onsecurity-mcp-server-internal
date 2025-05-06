# OnSecurity MCP Connector

A Model Context Protocol (MCP) connector for the OnSecurity API that allows Claude to query rounds, findings, and notifications.

## Installation

```bash
git clone https://github.com/onsecurity/onsecurity-mcp-server.git
cd onsecurity-mcp-server
npm install
npm run build
```

### Claude Desktop Configuration

To use this MCP server with Claude Desktop, you need to add an entry to your Claude Desktop configuration file

Add the following to your configuration file (adjust the paths as needed):

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
        "ONSECURITY_CLIENT_ID": "your_client_id"
      }
    }
  }
}
```

After adding this configuration, restart Claude Desktop, and you'll be able to access the OnSecurity tools through Claude.

## Usage

Once configured, Claude will have access to the following tools:

- `get-all-rounds`Fetches all rounds
- `get-all-findings`(optionally filtered by round_id)
- `get-all-notifications`: Gets notifications from OnSecurity

## Development

```bash
# Install dependencies
npm install

# Build the project
npm run build
```
