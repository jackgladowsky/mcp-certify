import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { Socket } from 'node:net';

export interface NetworkEvent {
  timestamp: number;
  type: 'dns' | 'http' | 'https';
  destination: string;
  method?: string;
  path?: string;
  body?: string;
}

export interface CaptureSession {
  events: NetworkEvent[];
  port: number;
  stop: () => void;
}

/**
 * Start a minimal HTTP capture proxy that logs all requests passing through.
 *
 * The proxy records destination host, method, path, and request body. The
 * harness sets HTTP_PROXY / HTTPS_PROXY in the child env to route traffic
 * through this proxy.
 *
 * For HTTPS CONNECT tunnels we record the destination but cannot inspect the
 * encrypted body -- that is an acceptable limitation for the MVP.
 */
export function startCapture(port?: number): Promise<CaptureSession> {
  return new Promise((resolve, reject) => {
    const events: NetworkEvent[] = [];
    const openSockets = new Set<Socket>();

    const server = createServer(
      (req: IncomingMessage, res: ServerResponse) => {
        // Normal HTTP proxy request -- the full URL is in req.url
        const targetUrl = req.url ?? '';
        let dest: URL | undefined;
        try {
          dest = new URL(targetUrl);
        } catch {
          // Not a full URL -- could be a relative path. Record as-is.
        }

        const chunks: Buffer[] = [];
        req.on('data', (chunk: Buffer) => chunks.push(chunk));
        req.on('end', () => {
          const body = Buffer.concat(chunks).toString('utf-8');
          events.push({
            timestamp: Date.now(),
            type: 'http',
            destination: dest ? dest.host : targetUrl,
            method: req.method,
            path: dest ? dest.pathname + dest.search : targetUrl,
            body: body.length > 0 ? body.slice(0, 4096) : undefined,
          });

          // Forward the request to the actual destination
          if (dest) {
            forwardRequest(dest, req, body, res);
          } else {
            res.writeHead(502, { 'Content-Type': 'text/plain' });
            res.end('Bad Gateway');
          }
        });
      },
    );

    // Handle CONNECT tunnels (HTTPS)
    server.on(
      'connect',
      (req: IncomingMessage, clientSocket: Socket, head: Buffer) => {
        const target = req.url ?? '';
        events.push({
          timestamp: Date.now(),
          type: 'https',
          destination: target,
          method: 'CONNECT',
        });

        // Establish a TCP connection to the real destination and relay
        const [host, portStr] = target.split(':');
        const targetPort = parseInt(portStr || '443', 10);

        import('node:net').then(({ connect: netConnect }) => {
          const serverSocket = netConnect(targetPort, host, () => {
            clientSocket.write(
              'HTTP/1.1 200 Connection Established\r\n\r\n',
            );
            if (head.length > 0) {
              serverSocket.write(head);
            }
            serverSocket.pipe(clientSocket);
            clientSocket.pipe(serverSocket);
          });
          openSockets.add(serverSocket);
          serverSocket.on('close', () => openSockets.delete(serverSocket));
          serverSocket.on('error', () => {
            clientSocket.end();
            openSockets.delete(serverSocket);
          });
          clientSocket.on('error', () => {
            serverSocket.end();
          });
        });
      },
    );

    server.on('connection', (socket: Socket) => {
      openSockets.add(socket);
      socket.on('close', () => openSockets.delete(socket));
    });

    server.listen(port ?? 0, '127.0.0.1', () => {
      const addr = server.address() as AddressInfo;
      const session: CaptureSession = {
        events,
        port: addr.port,
        stop: () => {
          for (const s of openSockets) {
            s.destroy();
          }
          openSockets.clear();
          server.close();
        },
      };
      resolve(session);
    });

    server.on('error', reject);
  });
}

/**
 * Forward an HTTP request to the real destination.
 */
function forwardRequest(
  dest: URL,
  originalReq: IncomingMessage,
  body: string,
  clientRes: ServerResponse,
): void {
  import('node:http')
    .then(({ request }) => {
      const proxyReq = request(
        {
          hostname: dest.hostname,
          port: dest.port || 80,
          path: dest.pathname + dest.search,
          method: originalReq.method,
          headers: {
            ...originalReq.headers,
            host: dest.host,
          },
        },
        (proxyRes) => {
          clientRes.writeHead(
            proxyRes.statusCode ?? 502,
            proxyRes.headers,
          );
          proxyRes.pipe(clientRes);
        },
      );

      proxyReq.on('error', () => {
        clientRes.writeHead(502, { 'Content-Type': 'text/plain' });
        clientRes.end('Bad Gateway');
      });

      if (body.length > 0) {
        proxyReq.write(body);
      }
      proxyReq.end();
    })
    .catch(() => {
      clientRes.writeHead(502, { 'Content-Type': 'text/plain' });
      clientRes.end('Bad Gateway');
    });
}

/**
 * Build environment variables that route HTTP(S) traffic through the capture proxy.
 */
export function proxyEnv(port: number): Record<string, string> {
  const url = `http://127.0.0.1:${port}`;
  return {
    HTTP_PROXY: url,
    HTTPS_PROXY: url,
    http_proxy: url,
    https_proxy: url,
    NO_PROXY: '',
    no_proxy: '',
  };
}

/**
 * Scan captured network events and arbitrary text for URLs / outbound destinations.
 * Returns the list of unique destination hosts observed.
 */
export function extractDestinations(
  events: NetworkEvent[],
  text?: string,
): string[] {
  const hosts = new Set<string>();

  for (const evt of events) {
    if (evt.destination) {
      // Strip port for deduplication
      const host = evt.destination.split(':')[0];
      if (host) hosts.add(host);
    }
  }

  // Also scan text for URLs (stdout/stderr from the server)
  if (text) {
    const urlRegex = /https?:\/\/([^/\s"')\]>]+)/gi;
    let match: RegExpExecArray | null;
    while ((match = urlRegex.exec(text)) !== null) {
      const host = match[1].split(':')[0];
      if (host) hosts.add(host);
    }
  }

  return [...hosts];
}
