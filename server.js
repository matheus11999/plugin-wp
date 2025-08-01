/**
 * LinkGate Redirector API Server
 * Handles token validation and domain authorization
 */

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const morgan = require('morgan');
const compression = require('compression');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');
const winston = require('winston');
require('dotenv').config();

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;
const ENV = process.env.NODE_ENV || 'production';
const BACKEND_DOMAIN = process.env.BACKEND_DOMAIN || `http://localhost:${PORT}`;

// Initialize Express app configuration
console.log('🚀 Starting LinkGate API Server...');

// Configure Winston logger
const logger = winston.createLogger({
    level: ENV === 'development' ? 'debug' : 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    defaultMeta: { service: 'linkgate-api' },
    transports: [
        new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
        new winston.transports.File({ filename: 'logs/combined.log' }),
    ],
});

// Add console transport in development
if (ENV === 'development') {
    logger.add(new winston.transports.Console({
        format: winston.format.simple()
    }));
}

// Handle uncaught exceptions and unhandled promise rejections
process.on('uncaughtException', (error) => {
    console.error('❌ Uncaught Exception:', error);
    logger.error('Uncaught Exception:', error);
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
    logger.error('Unhandled Rejection:', { promise, reason });
    process.exit(1);
});

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

// CORS configuration - Allow everything for now
const corsOptions = {
    origin: true, // Allow all origins
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS', 'PUT', 'DELETE', 'PATCH'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Origin', 'Accept', 'X-Request-ID'],
    exposedHeaders: ['X-Request-ID'],
    optionsSuccessStatus: 200 // Some legacy browsers (IE11, various SmartTVs) choke on 204
};

app.use(cors(corsOptions));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: {
        error: 'Too many requests from this IP, please try again later.',
        code: 'RATE_LIMIT_EXCEEDED'
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        logger.warn(`Rate limit exceeded for IP: ${req.ip}`);
        res.status(429).json({
            error: 'Too many requests from this IP, please try again later.',
            code: 'RATE_LIMIT_EXCEEDED'
        });
    }
});

app.use(limiter);

// Strict rate limiting for verification endpoint
const verifyLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 minute
    max: 10, // Limit each IP to 10 verification requests per minute
    message: {
        error: 'Too many verification attempts, please try again later.',
        code: 'VERIFY_RATE_LIMIT_EXCEEDED'
    }
});

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Compression middleware
app.use(compression());

// Logging middleware
app.use(morgan('combined', {
    stream: {
        write: (message) => logger.info(message.trim())
    }
}));

// Request ID middleware
app.use((req, res, next) => {
    req.id = crypto.randomUUID();
    res.setHeader('X-Request-ID', req.id);
    
    // Log all incoming requests for debugging
    console.log(`📥 [${new Date().toISOString()}] ${req.method} ${req.originalUrl} from ${req.ip}`);
    console.log(`📋 Headers:`, JSON.stringify(req.headers, null, 2));
    if (req.body && Object.keys(req.body).length > 0) {
        console.log(`📦 Body:`, JSON.stringify(req.body, null, 2));
    }
    
    next();
});

// Security headers middleware
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
});

// Trust proxy for rate limiting
app.set('trust proxy', 1);

// Token validation cache (in production, use Redis)
const tokenCache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

// Load valid tokens from file
async function loadValidTokens() {
    try {
        const tokensPath = path.join(__dirname, 'valid_tokens.json');
        const data = await fs.readFile(tokensPath, 'utf8');
        const tokens = JSON.parse(data);
        
        if (!tokens.tokens || !Array.isArray(tokens.tokens)) {
            throw new Error('Invalid tokens file format');
        }
        
        logger.info(`Loaded ${tokens.tokens.length} valid tokens`);
        return tokens;
    } catch (error) {
        logger.error('Failed to load valid tokens:', error);
        throw new Error('Token configuration not available');
    }
}

// Validate token and domain
async function validateTokenDomain(token, domain) {
    try {
        console.log(`🔄 validateTokenDomain called with token: "${token}", domain: "${domain}"`);
        
        const cacheKey = `${token}:${domain}`;
        
        // Check cache first
        if (tokenCache.has(cacheKey)) {
            const cached = tokenCache.get(cacheKey);
            if (Date.now() < cached.expires) {
                console.log(`📋 Cache hit for token validation: ${cacheKey}`);
                logger.debug(`Cache hit for token validation: ${cacheKey}`);
                return cached.valid;
            }
            tokenCache.delete(cacheKey);
        }
        
        console.log(`📂 Loading valid tokens from file...`);
        const validTokens = await loadValidTokens();
        console.log(`📋 Loaded ${validTokens.tokens.length} tokens`);
        
        let isValid = false;
        
        // Normalize domain (remove protocol, www, trailing slash)
        const normalizedDomain = domain
            .replace(/^https?:\/\//, '')
            .replace(/^www\./, '')
            .replace(/\/$/, '')
            .toLowerCase();
        
        console.log(`🔧 Normalized domain: "${normalizedDomain}"`);
        
        for (const tokenObj of validTokens.tokens) {
            console.log(`🔍 Checking token: "${tokenObj.token}" against provided: "${token}"`);
            
            if (tokenObj.token === token) {
                console.log(`✅ Token match found! Checking domains...`);
                console.log(`📋 Allowed domains:`, tokenObj.domains);
                
                // Check if domain is in allowed domains
                for (const allowedDomain of tokenObj.domains) {
                    const normalizedAllowed = allowedDomain
                        .replace(/^https?:\/\//, '')
                        .replace(/^www\./, '')
                        .replace(/\/$/, '')
                        .toLowerCase();
                    
                    console.log(`🔍 Comparing "${normalizedDomain}" with "${normalizedAllowed}"`);
                    
                    if (normalizedDomain === normalizedAllowed) {
                        console.log(`✅ Domain match found!`);
                        isValid = true;
                        break;
                    }
                }
                break;
            }
        }
        
        // Cache the result
        tokenCache.set(cacheKey, {
            valid: isValid,
            expires: Date.now() + CACHE_TTL
        });
        
        console.log(`🏁 Final validation result: ${isValid} for ${normalizedDomain}`);
        logger.info(`Token validation result: ${isValid} for ${normalizedDomain}`);
        return isValid;
        
    } catch (error) {
        console.log(`💥 Token validation error:`, error);
        logger.error('Token validation error:', error);
        return false;
    }
}

// Health check endpoint
app.get('/health', (req, res) => {
    console.log(`❤️  Health check request from ${req.ip}`);
    
    const healthData = {
        status: 'healthy',
        service: 'LinkGate API Server',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        version: '1.0.0',
        environment: ENV,
        port: PORT,
        requestId: req.id
    };
    
    console.log(`✅ Health check response:`, healthData);
    res.json(healthData);
});

// API status endpoint
app.get('/api/status', (req, res) => {
    res.json({
        service: 'LinkGate API Server',
        version: '1.0.0',
        status: 'operational',
        domain: BACKEND_DOMAIN,
        timestamp: new Date().toISOString(),
        endpoints: {
            verify: '/api/verify',
            health: '/health',
            status: '/api/status'
        },
        configuration: {
            environment: ENV,
            port: PORT,
            corsEnabled: true,
            rateLimitEnabled: true
        }
    });
});

// Token verification endpoint
app.post('/api/verify', [
    verifyLimiter,
    body('token')
        .isLength({ min: 1, max: 200 })
        .withMessage('Token must be between 1 and 200 characters')
        .matches(/^[a-zA-Z0-9\-_\.]+$/)
        .withMessage('Token contains invalid characters'),
    body('domain')
        .isURL({ protocols: ['http', 'https'], require_protocol: true })
        .withMessage('Domain must be a valid URL with protocol')
        .isLength({ max: 255 })
        .withMessage('Domain too long')
], async (req, res) => {
    const requestId = req.id;
    
    console.log(`🔐 Token verification request ${requestId} started`);
    console.log(`📦 Request body:`, req.body);
    
    try {
        // Check validation errors
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            console.log(`❌ Validation errors for request ${requestId}:`, errors.array());
            logger.warn(`Validation errors for request ${requestId}:`, errors.array());
            return res.status(400).json({
                valid: false,
                error: 'Invalid request parameters',
                details: errors.array(),
                requestId
            });
        }
        
        const { token, domain } = req.body;
        
        console.log(`🔍 Verifying token "${token}" for domain "${domain}" [${requestId}]`);
        logger.info(`Token verification request ${requestId}: ${domain}`);
        
        // Additional security checks
        if (token.includes(' ') || domain.includes(' ')) {
            console.log(`⚠️  Suspicious request ${requestId}: contains spaces`);
            logger.warn(`Suspicious request ${requestId}: contains spaces`);
            return res.status(400).json({
                valid: false,
                error: 'Invalid parameters format',
                requestId
            });
        }
        
        // Validate token and domain
        console.log(`🔄 Starting token validation...`);
        const isValid = await validateTokenDomain(token, domain);
        console.log(`🔍 Token validation result: ${isValid}`);
        
        const response = {
            valid: isValid,
            timestamp: new Date().toISOString(),
            requestId,
            debug: {
                receivedToken: token,
                receivedDomain: domain,
                validationResult: isValid
            }
        };
        
        if (isValid) {
            console.log(`✅ Token verification successful for ${domain} [${requestId}]`);
            logger.info(`Token verification successful for ${domain} [${requestId}]`);
        } else {
            console.log(`❌ Token verification failed for ${domain} [${requestId}]`);
            logger.warn(`Token verification failed for ${domain} [${requestId}]`);
        }
        
        console.log(`📤 Sending response:`, response);
        res.json(response);
        
    } catch (error) {
        console.log(`💥 Token verification error for request ${requestId}:`, error);
        logger.error(`Token verification error for request ${requestId}:`, error);
        res.status(500).json({
            valid: false,
            error: 'Internal server error',
            requestId,
            debug: {
                errorMessage: error.message,
                errorStack: error.stack
            }
        });
    }
});


const referers = [
    'https://www.google.com', 
    'https://www.facebook.com', 
    'https://www.bing.com', 
    'https://www.yahoo.com'
];

app.get('/aguarde', async (req, res) => {
    const encodedUrl = req.query.a;
    const debugMode = req.query.debug === 'true';

    if (!encodedUrl) {
        return res.status(400).send('Parâmetro "a" não encontrado.');
    }

    try {
        let redirectUrl;

        if (debugMode) {
            redirectUrl = '/check-referer';
            logger.info(`Modo de depuração ativado. Redirecionando para ${redirectUrl}`);
        } else {
            const validTokens = await loadValidTokens();
            const allDomains = validTokens.tokens.flatMap(t => t.domains);
            if (allDomains.length === 0) {
                logger.error('Nenhum domínio de redirecionamento configurado.');
                return res.status(500).send('Nenhum domínio de redirecionamento configurado.');
            }

            const randomDomain = allDomains[Math.floor(Math.random() * allDomains.length)];
            redirectUrl = `${randomDomain}/redirect.php?url=${encodedUrl}`;
        }
        
        let htmlContent = await fs.readFile(path.join(__dirname, 'wait.html'), 'utf8');
        
        const nonce = crypto.randomBytes(16).toString('base64');
        const script = `<script nonce="${nonce}">
            setTimeout(function() {
                window.location.replace('${redirectUrl}');
            }, 2000);
        </script>`;

        htmlContent = htmlContent.replace('<!-- SCRIPT_PLACEHOLDER -->', script);

        res.setHeader('Content-Security-Policy', `script-src 'self' 'nonce-${nonce}'`);
        res.send(htmlContent);
    } catch (error) {
        logger.error('Erro no endpoint /aguarde:', error);
        res.status(500).send('Erro interno do servidor.');
    }
});

app.get('/check-referer', (req, res) => {
    const referer = req.headers.referer || 'Nenhum referer encontrado.';
    const userAgent = req.headers['user-agent'] || 'Nenhum user-agent encontrado.';
    const ip = req.ip;

    const htmlResponse = `
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Verificador de Referer</title>
        <style>
            body { font-family: sans-serif; background-color: #f4f4f4; color: #333; margin: 20px; }
            .container { max-width: 800px; margin: auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            h1 { color: #0056b3; }
            .detail { margin-bottom: 15px; padding: 10px; border-left: 4px solid #0056b3; background-color: #e7f3ff; word-wrap: break-word; }
            .detail strong { color: #004085; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Detalhes da Requisição</h1>
            <div class="detail">
                <strong>Referer:</strong>
                <p>${referer}</p>
            </div>
            <div class="detail">
                <strong>User-Agent:</strong>
                <p>${userAgent}</p>
            </div>
            <div class="detail">
                <strong>IP do Cliente:</strong>
                <p>${ip}</p>
            </div>
        </div>
    </body>
    </html>
    `;
    res.send(htmlResponse);
});

// Analytics endpoint (optional)

app.post('/api/analytics', [
    body('event').isIn(['redirect_started', 'redirect_completed', 'ad_clicked']),
    body('timestamp').isISO8601(),
    body('domain').optional().isURL()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            error: 'Invalid analytics data',
            details: errors.array()
        });
    }
    
    const { event, timestamp, domain, ...metadata } = req.body;
    
    // Log analytics event (in production, store in database)
    logger.info('Analytics event:', {
        event,
        timestamp,
        domain,
        metadata,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        requestId: req.id
    });
    
    res.json({ success: true, requestId: req.id });
});

// 404 handler
app.use('*', (req, res) => {
    logger.warn(`404 Not Found: ${req.method} ${req.originalUrl} from ${req.ip}`);
    res.status(404).json({
        error: 'Endpoint not found',
        method: req.method,
        path: req.originalUrl,
        timestamp: new Date().toISOString()
    });
});

// Global error handler
app.use((err, req, res, next) => {
    logger.error('Unhandled error:', {
        error: err.message,
        stack: err.stack,
        requestId: req.id,
        ip: req.ip,
        method: req.method,
        url: req.originalUrl
    });
    
    if (err.name === 'ValidationError') {
        return res.status(400).json({
            error: 'Validation error',
            message: err.message,
            requestId: req.id
        });
    }
    
    if (err.message === 'Not allowed by CORS') {
        return res.status(403).json({
            error: 'CORS policy violation',
            message: 'Origin not allowed',
            requestId: req.id
        });
    }
    
    res.status(500).json({
        error: 'Internal server error',
        requestId: req.id,
        timestamp: new Date().toISOString()
    });
});

// Graceful shutdown handlers are now inside startServer() function

// Error handling for server startup
const startServer = () => {
    const server = app.listen(PORT, '0.0.0.0', () => {
        console.log(`🚀 LinkGate API Server iniciado com sucesso!`);
        console.log(`📍 Porta: ${PORT}`);
        console.log(`🌍 Ambiente: ${ENV}`);
        console.log(`🔗 Domínio: ${BACKEND_DOMAIN}`);
        console.log(`❤️  Health check: ${BACKEND_DOMAIN}/health`);
        console.log(`📊 Status da API: ${BACKEND_DOMAIN}/api/status`);
        console.log(`⏰ Servidor iniciado em: ${new Date().toISOString()}`);
        console.log(`🔧 Servidor pronto para receber conexões!`);
        
        logger.info(`LinkGate API Server started on port ${PORT}`);
        
        // Clear token cache periodically
        const cacheCleanup = setInterval(() => {
            const now = Date.now();
            let cleanedCount = 0;
            for (const [key, value] of tokenCache.entries()) {
                if (now >= value.expires) {
                    tokenCache.delete(key);
                    cleanedCount++;
                }
            }
            if (cleanedCount > 0) {
                logger.debug(`Cleaned ${cleanedCount} expired cache entries`);
            }
        }, 60000); // Clean every minute
        
        // Graceful shutdown handler
        const gracefulShutdown = (signal) => {
            logger.info(`${signal} received, shutting down gracefully`);
            clearInterval(cacheCleanup);
            server.close(() => {
                logger.info('✅ Server closed successfully');
                process.exit(0);
            });
            
            // Force close after 10 seconds
            setTimeout(() => {
                logger.error('❌ Could not close connections in time, forcefully shutting down');
                process.exit(1);
            }, 10000);
        };
        
        process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
        process.on('SIGINT', () => gracefulShutdown('SIGINT'));
    });
    
    server.on('error', (error) => {
        if (error.code === 'EADDRINUSE') {
            logger.error(`❌ Port ${PORT} is already in use. Please check if another process is running on this port.`);
            logger.error(`💡 Try: lsof -ti:${PORT} | xargs kill -9`);
        } else if (error.code === 'EACCES') {
            logger.error(`❌ Permission denied. Cannot bind to port ${PORT}. Try using a port number > 1024 or run with sudo.`);
        } else if (error.code === 'ENOTFOUND') {
            logger.error(`❌ Address not found. Check your network configuration.`);
        } else {
            logger.error(`❌ Server startup error:`, error);
        }
        process.exit(1);
    });
    
    return server;
};

// Start the server
const server = startServer();

module.exports = app;