#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

// Create the server instance
const server = new Server(
  {
    name: "hello-world-mcp-server",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// List available tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "hello",
        description: "A simple hello world tool that greets the user",
        inputSchema: {
          type: "object",
          properties: {
            name: {
              type: "string",
              description: "Name to greet (optional)",
            },
          },
        },
      },
      {
        name: "get_current_time",
        description: "Get the current date and time",
        inputSchema: {
          type: "object",
          properties: {},
        },
      },
    ],
  };
});

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  switch (name) {
    case "hello": {
      const userName = args?.name || "World";
      return {
        content: [
          {
            type: "text",
            text: `Hello, ${userName}! This is a simple MCP server responding to your greeting. 👋`,
          },
        ],
      };
    }

    case "get_current_time": {
      const now = new Date();
      return {
        content: [
          {
            type: "text",
            text: `Current date and time: ${now.toLocaleString()}`,
          },
        ],
      };
    }

    default:
      throw new Error(`Unknown tool: ${name}`);
  }
});

// Start the server using stdio transport
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Hello World MCP Server running on stdio");
}

main().catch((error) => {
  console.error("Server failed to start:", error);
  process.exit(1);
});