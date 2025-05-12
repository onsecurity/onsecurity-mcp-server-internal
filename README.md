### Claude Desktop Configuration

To use this MCP server with Claude Desktop, you need to add an entry to your Claude Desktop configuration file

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
        "ONSECURITY_CLIENT_ID": "your_client_id",
        "ONSECURITY_API_BASE": "https://uat.dev.onsecurity.io/api/v2 OR https://app.onsecurity.io/api/v2"
      }
    }
  }
}
```

After adding this configuration, restart Claude Desktop, and you'll be able to access the OnSecurity tools through Claude.

## Usage

Once configured, Claude will have access to the following tools:

- `get-rounds`
- `get-findings`
- `get-notifications`
- `get-prerequisites`

#### Example Questions
- Give me a summary of my most recent pentest/scan.
- Show me trends across my pentests as a graph.
- What can I address to make the most impact most quickly on my most recent pentest?
- I would like summaries for different types of stakeholders on the state of our recent pentest engagemenets - eg high level, technical, managerial etc
- Do I need to action anything to prevent test getting held up?
- Are there any new findings?

*Note: It is useful sometimes to configure Claude to "Extended thinking" for some questions.*
