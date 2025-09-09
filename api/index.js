const { createServer } = require('http');
const { parse } = require('url');

// Simple serverless handler that works with Vercel
module.exports = async (req, res) => {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  
  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  // Basic health check
  if (req.url === '/health') {
    res.status(200).json({ status: 'ok', service: 'auth-service' });
    return;
  }

  // Default response
  res.status(200).json({ 
    message: 'Welcome to Nexus Auth Service 🤝',
    service: 'auth-service',
    version: '0.1.0'
  });
};
