# Hello World MCP Server

A simple Model Context Protocol (MCP) server that provides basic "hello world" functionality for Claude Desktop.

## Features

This MCP server provides two simple tools:
- **hello**: Greets the user with a customizable name
- **get_current_time**: Returns the current date and time

## Prerequisites

1. **Node.js** (version 18 or higher)
   - Download from [nodejs.org](https://nodejs.org/)
   - Or install via Homebrew: `brew install node`

2. **Claude Desktop** application installed on your machine

## Installation

1. **Clone or download this project** to your local machine

2. **Install dependencies**:
   ```bash
   cd testmcppyshark
   npm install
   ```

3. **Build the TypeScript code**:
   ```bash
   npm run build
   ```

## Configuration

### Step 1: Update the configuration file

Edit the `claude-desktop-config.json` file and update the path to match your actual project location:

```json
{
  "mcpServers": {
    "hello-world": {
      "command": "node",
      "args": ["/FULL/PATH/TO/YOUR/PROJECT/testmcppyshark/build/index.js"],
      "env": {}
    }
  }
}
```

**Important**: Replace `/FULL/PATH/TO/YOUR/PROJECT/` with the actual absolute path to your project directory.

### Step 2: Configure Claude Desktop

1. **Locate Claude Desktop's configuration directory**:
   - **macOS**: `~/Library/Application Support/Claude/`
   - **Windows**: `%APPDATA%\Claude\`
   - **Linux**: `~/.config/Claude/`

2. **Copy the configuration**:
   ```bash
   # On macOS
   cp claude-desktop-config.json ~/Library/Application\ Support/Claude/claude_desktop_config.json
   
   # On Windows (PowerShell)
   Copy-Item claude-desktop-config.json $env:APPDATA\Claude\claude_desktop_config.json
   
   # On Linux
   cp claude-desktop-config.json ~/.config/Claude/claude_desktop_config.json
   ```

   **Note**: If you already have a `claude_desktop_config.json` file, you'll need to merge the `mcpServers` section into your existing configuration.

3. **Restart Claude Desktop** completely (quit and reopen)

## Usage

Once configured, you can use the MCP server tools in Claude Desktop:

1. **Hello Tool**:
   - Ask Claude: "Can you say hello to me?"
   - Or: "Use the hello tool to greet John"

2. **Current Time Tool**:
   - Ask Claude: "What's the current time?"
   - Or: "Use the get_current_time tool"

## Development

### Available Scripts

- `npm run build` - Compile TypeScript to JavaScript
- `npm run start` - Run the compiled server
- `npm run dev` - Run the server in development mode with tsx

### Project Structure

```
testmcppyshark/
├── src/
│   └── index.ts              # Main MCP server implementation
├── build/                    # Compiled JavaScript (after npm run build)
├── package.json              # Node.js project configuration
├── tsconfig.json             # TypeScript configuration
├── claude-desktop-config.json # Claude Desktop configuration template
└── README.md                 # This file
```

## Troubleshooting

### Server not appearing in Claude Desktop

1. **Check the path**: Ensure the path in `claude_desktop_config.json` is correct and points to the compiled `build/index.js` file
2. **Verify build**: Run `npm run build` to ensure the TypeScript is compiled
3. **Check file permissions**: Ensure the built file is executable
4. **Restart Claude Desktop**: Completely quit and restart the application
5. **Check logs**: Look in Claude Desktop's logs for any error messages

### "Command not found" errors

- Ensure Node.js is installed: `node --version`
- Ensure npm is available: `npm --version`
- If missing, install Node.js from [nodejs.org](https://nodejs.org/)

### TypeScript compilation errors

- Ensure all dependencies are installed: `npm install`
- Check that TypeScript is installed: `npx tsc --version`

## Extending the Server

To add more tools to your MCP server:

1. Add the new tool to the `tools` array in the `ListToolsRequestSchema` handler
2. Add a new case in the `CallToolRequestSchema` handler
3. Rebuild with `npm run build`
4. Restart Claude Desktop

## License

MIT License - see package.json for details.