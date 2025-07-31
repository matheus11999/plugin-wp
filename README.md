# LinkGate API Server

A secure Node.js backend server for the LinkGate Redirector WordPress plugin that handles token validation and domain authorization.

## Features

- **Token Validation**: Secure API token verification against authorized domains
- **Domain Authorization**: Ensures tokens are only valid for specified domains
- **Rate Limiting**: Prevents abuse with configurable rate limits
- **Security Headers**: Comprehensive security headers and CORS protection
- **Request Logging**: Detailed logging for monitoring and debugging
- **Health Monitoring**: Built-in health check and status endpoints
- **Analytics Support**: Optional analytics event tracking
- **Caching**: In-memory token validation caching for performance

## Quick Start

### Prerequisites

- Node.js 16.0.0 or higher
- npm 8.0.0 or higher

### Installation

1. Clone or extract the API server files
2. Install dependencies:
   ```bash
   npm install
   ```

3. Configure environment variables:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. Update the `valid_tokens.json` file with your tokens and domains

5. Start the server:
   ```bash
   # Production
   npm start
   
   # Development with auto-reload
   npm run dev
   ```

The server will start on `http://localhost:3000` by default.

## Configuration

### Environment Variables

Copy `.env.example` to `.env` and configure:

- `NODE_ENV`: Environment (production/development)
- `PORT`: Server port (default: 3000)
- `ALLOWED_ORIGINS`: Comma-separated CORS origins
- `LOG_LEVEL`: Logging level (error/warn/info/debug)

### Token Configuration

Edit `valid_tokens.json` to add your tokens and authorized domains:

```json
{
  "tokens": [
    {
      "token": "your_unique_token_here",
      "domains": [
        "https://yourwordpressite.com",
        "https://www.yourwordpressite.com"
      ],
      "created": "2024-01-01T00:00:00Z",
      "expires": "2025-12-31T23:59:59Z",
      "description": "Token description"
    }
  ]
}
```

## API Endpoints

### POST /api/verify

Validates a token against a domain.

**Request:**
```json
{
  "token": "your_token_here",
  "domain": "https://yourdomain.com"
}
```

**Response:**
```json
{
  "valid": true,
  "timestamp": "2024-01-01T12:00:00Z",
  "requestId": "uuid-here"
}
```

### GET /health

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00Z",
  "uptime": 12345,
  "version": "1.0.0",
  "environment": "production"
}
```

### GET /api/status

API status and information.

**Response:**
```json
{
  "service": "LinkGate API Server",
  "version": "1.0.0",
  "status": "operational",
  "timestamp": "2024-01-01T12:00:00Z",
  "endpoints": {
    "verify": "/api/verify",
    "health": "/health",
    "status": "/api/status"
  }
}
```

## Security Features

- **Helmet.js**: Security headers and protections
- **CORS**: Configurable cross-origin resource sharing
- **Rate Limiting**: IP-based request rate limiting
- **Input Validation**: Request parameter validation and sanitization
- **Request IDs**: Unique request tracking for debugging
- **Security Headers**: XSS, clickjacking, and content-type protections

## Rate Limits

- **General API**: 100 requests per 15 minutes per IP
- **Token Verification**: 10 requests per minute per IP

## Logging

The server uses Winston for logging with the following levels:

- **Error**: Application errors and exceptions
- **Warn**: Warning conditions (failed validations, rate limits)
- **Info**: Informational messages (successful requests, server start)
- **Debug**: Debug information (development only)

Logs are written to:
- `logs/error.log`: Error level logs only
- `logs/combined.log`: All log levels
- Console: Development mode only

## Deployment

### Production Deployment

1. **Environment Setup**:
   ```bash
   NODE_ENV=production
   PORT=3000
   ```

2. **Process Management** (using PM2):
   ```bash
   npm install -g pm2
   pm2 start server.js --name linkgate-api
   pm2 startup
   pm2 save
   ```

3. **Reverse Proxy** (Nginx example):
   ```nginx
   server {
       listen 80;
       server_name api.yourdomain.com;
       
       location / {
           proxy_pass http://localhost:3000;
           proxy_http_version 1.1;
           proxy_set_header Upgrade $http_upgrade;
           proxy_set_header Connection 'upgrade';
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
           proxy_cache_bypass $http_upgrade;
       }
   }
   ```

4. **SSL Certificate** (using Let's Encrypt):
   ```bash
   certbot --nginx -d api.yourdomain.com
   ```

### Docker Deployment

Create a `Dockerfile`:

```dockerfile
FROM node:18-alpine

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

COPY . .

EXPOSE 3000
USER node

CMD ["npm", "start"]
```

Build and run:
```bash
docker build -t linkgate-api .
docker run -p 3000:3000 --env-file .env linkgate-api
```

## Monitoring

### Health Checks

Monitor the `/health` endpoint for server status:

```bash
curl http://localhost:3000/health
```

### Log Monitoring

Monitor log files for errors and suspicious activity:

```bash
tail -f logs/error.log
tail -f logs/combined.log
```

### Performance Monitoring

Consider using tools like:
- **New Relic**: Application performance monitoring
- **DataDog**: Infrastructure and application monitoring
- **Prometheus + Grafana**: Open-source monitoring stack

## Troubleshooting

### Common Issues

1. **Port Already in Use**:
   ```
   Error: listen EADDRINUSE :::3000
   ```
   Solution: Change the PORT in `.env` or kill the process using port 3000

2. **CORS Errors**:
   ```
   Access to fetch at 'http://api.domain.com' from origin 'https://wordpress.site' has been blocked by CORS
   ```
   Solution: Add the WordPress domain to `ALLOWED_ORIGINS` in `.env`

3. **Token Validation Failing**:
   - Check that the token exists in `valid_tokens.json`
   - Verify the domain format matches exactly (including protocol)
   - Check server logs for validation errors

4. **Rate Limit Errors**:
   ```
   Too many requests from this IP
   ```
   Solution: Wait for the rate limit window to reset or adjust limits in code

### Debug Mode

Enable debug logging:
```bash
LOG_LEVEL=debug npm run dev
```

## Support

For support and documentation:
- Check the server logs first
- Use the `/health` endpoint to verify server status
- Review the `valid_tokens.json` configuration
- Check CORS and rate limiting settings

## License

Commercial License - LinkGate Team