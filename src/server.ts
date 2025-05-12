import express, { Request, Response, NextFunction } from 'express';
import { randomUUID } from 'node:crypto';
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { isInitializeRequest } from "@modelcontextprotocol/sdk/types.js";
import { InMemoryEventStore } from "@modelcontextprotocol/sdk/examples/shared/inMemoryEventStore.js";
import cors from 'cors';
import 'dotenv/config';

// Environment variables
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '127.0.0.1'; // Default to localhost for security
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'];

// Create Express app
const app = express();

// Add security headers middleware
app.use((req: Request, res: Response, next: NextFunction) => {
  // Set strict content security policy
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  // Prevent MIME type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');
  // Prevent clickjacking
  res.setHeader('X-Frame-Options', 'DENY');
  // Enable XSS protection
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

// Setup CORS with origin validation
app.use(cors({
  origin: (origin: string | undefined, callback: (err: Error | null, allow?: boolean) => void) => {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);
    
    // Check if origin is in the allowed list
    if (ALLOWED_ORIGINS.indexOf(origin) === -1) {
      const msg = `The CORS policy for this site does not allow access from the specified Origin: ${origin}`;
      return callback(new Error(msg), false);
    }
    
    return callback(null, true);
  },
  methods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Mcp-Session-Id', 'Last-Event-Id', 'Accept'],
  credentials: true,
}));

// Parse JSON body for POST requests
app.use(express.json({ limit: '4mb' }));

// Map to store transports by session ID
const transports: Record<string, StreamableHTTPServerTransport> = {};

// Setup server with the main OnSecurity MCP instance
export function setupHttpServer(mcpServer: McpServer) {
  // Handle POST requests (JSON-RPC messages from client)
  app.post('/mcp', async (req: Request, res: Response) => {
    console.log('Received MCP request');
    
    try {
      // Check for existing session ID
      const sessionId = req.headers['mcp-session-id'] as string;
      
      // Case 1: Request with valid session ID
      if (sessionId && transports[sessionId]) {
        const transport = transports[sessionId];
        await transport.handleRequest(req, res, req.body);
        return;
      } 
      
      // Case 2: Initialize request without session ID
      if (!sessionId && isInitializeRequest(req.body)) {
        const eventStore = new InMemoryEventStore();
        const transport = new StreamableHTTPServerTransport({
          sessionIdGenerator: () => randomUUID(),
          eventStore, // Enable resumability
          onsessioninitialized: (newSessionId) => {
            console.log(`Session initialized with ID: ${newSessionId}`);
            transports[newSessionId] = transport;
          }
        });
        
        // Set up onclose handler to clean up transport when closed
        transport.onclose = () => {
          const sid = transport.sessionId;
          if (sid && transports[sid]) {
            console.log(`Transport closed for session ${sid}, removing from transports map`);
            delete transports[sid];
          }
        };
        
        // Connect the transport to the MCP server BEFORE handling the request
        await mcpServer.connect(transport);
        await transport.handleRequest(req, res, req.body);
        return;
      } 
      
      // Case 3: Invalid request - no session ID or not initialization request
      res.status(400).json({
        jsonrpc: '2.0',
        error: {
          code: -32000,
          message: 'Bad Request: No valid session ID provided',
        },
        id: null,
      });
    } 
    catch (error) {
      console.error('Error handling MCP request:', error);
      if (!res.headersSent) {
        res.status(500).json({
          jsonrpc: '2.0',
          error: {
            code: -32603,
            message: 'Internal server error',
          },
          id: null,
        });
      }
    }
  });

  // Handle GET requests for SSE streams
  app.get('/mcp', async (req: Request, res: Response) => {
    const sessionId = req.headers['mcp-session-id'] as string;
    
    if (!sessionId || !transports[sessionId]) {
      res.status(400).send('Invalid or missing session ID');
      return;
    }
    
    // Check for Last-Event-ID header for resumability
    const lastEventId = req.headers['last-event-id'] as string;
    if (lastEventId) {
      console.log(`Client reconnecting with Last-Event-ID: ${lastEventId}`);
    } else {
      console.log(`Establishing new SSE stream for session ${sessionId}`);
    }
    
    const transport = transports[sessionId];
    await transport.handleRequest(req, res);
  });

  // Handle DELETE requests for session termination
  app.delete('/mcp', async (req: Request, res: Response) => {
    const sessionId = req.headers['mcp-session-id'] as string;
    
    if (!sessionId || !transports[sessionId]) {
      res.status(400).send('Invalid or missing session ID');
      return;
    }
    
    console.log(`Received session termination request for session ${sessionId}`);
    
    try {
      const transport = transports[sessionId];
      await transport.handleRequest(req, res);
    } catch (error) {
      console.error('Error handling session termination:', error);
      if (!res.headersSent) {
        res.status(500).send('Error processing session termination');
      }
    }
  });

  // Start server function
  return {
    start: () => {
      return new Promise<void>((resolve) => {
        app.listen(Number(PORT), HOST, () => {
          console.log(`MCP Streamable HTTP Server listening on ${HOST}:${PORT}`);
          resolve();
        });
      });
    },
    close: async () => {
      console.log('Shutting down HTTP server...');
      
      // Close all active transports to properly clean up resources
      for (const sessionId in transports) {
        try {
          console.log(`Closing transport for session ${sessionId}`);
          await transports[sessionId].close();
          delete transports[sessionId];
        } catch (error) {
          console.error(`Error closing transport for session ${sessionId}:`, error);
        }
      }
      
      console.log('HTTP Server shutdown complete');
    }
  };
} 