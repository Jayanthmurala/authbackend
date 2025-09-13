// Minimal working version for Vercel deployment
export default async function handler(request: Request): Promise<Response> {
  try {
    // Simple health check and basic routes
    const url = new URL(request.url);
    const path = url.pathname;
    
    if (path === "/" || path === "/health") {
      return new Response(JSON.stringify({ 
        message: "Welcome To NexUs 🤝", 
        status: "ok", 
        timestamp: new Date().toISOString(),
        service: "auth-service"
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    if (path === "/docs") {
      return new Response(`
        <!DOCTYPE html>
        <html>
        <head><title>Nexus Auth Service</title></head>
        <body>
          <h1>Nexus Auth Service</h1>
          <p>Service is running successfully!</p>
          <ul>
            <li><a href="/">Home</a></li>
            <li><a href="/health">Health Check</a></li>
          </ul>
        </body>
        </html>
      `, {
        status: 200,
        headers: { 'Content-Type': 'text/html' }
      });
    }
    
    return new Response(JSON.stringify({ 
      error: 'Not Found',
      path: path,
      message: 'Endpoint not found'
    }), {
      status: 404,
      headers: { 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('Auth service error:', error);
    return new Response(JSON.stringify({ 
      error: 'Internal Server Error',
      message: 'Something went wrong'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}
