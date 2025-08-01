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
            scriptSrc: ["'self'", "'unsafe-inline'"],
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


// Lista de referrers para spoofing aleatório (top 5 geradores de tráfego)
const FAKE_REFERRERS = [
    // Google (maior gerador de tráfego)
    'https://www.google.com/search?q=',
    'https://www.google.com.br/search?q=',
    'https://images.google.com/',
    
    // Facebook (segundo maior)
    'https://www.facebook.com/',
    'https://m.facebook.com/',
    'https://www.facebook.com/l.php?u=',
    
    // YouTube (terceiro maior)
    'https://www.youtube.com/',
    'https://m.youtube.com/',
    
    // Instagram (quarto maior)
    'https://www.instagram.com/',
    'https://www.instagram.com/explore/',
    
    // X/Twitter (quinto maior)
    'https://x.com/',
    'https://t.co/'
];

// Função para obter um referrer aleatório
function getRandomReferrer() {
    const randomIndex = Math.floor(Math.random() * FAKE_REFERRERS.length);
    const baseReferrer = FAKE_REFERRERS[randomIndex];
    
    // Se for um referrer de busca, adiciona um termo aleatório
    if (baseReferrer.includes('?q=') && baseReferrer.endsWith('?q=')) {
        const searchTerms = [
            'technology news', 'best practices', 'tutorial guide', 'how to learn',
            'latest updates', 'programming tips', 'web development', 'digital marketing',
            'online tools', 'productivity apps', 'social media trends', 'tech reviews'
        ];
        const randomTerm = searchTerms[Math.floor(Math.random() * searchTerms.length)];
        return baseReferrer + encodeURIComponent(randomTerm);
    }
    
    return baseReferrer;
}

// Lista de User-Agents mais comuns
const FAKE_USER_AGENTS = [
    // Chrome Windows (mais comum)
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    
    // Chrome Mac
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    
    // Firefox Windows
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
    
    // Safari Mac
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15',
    
    // Mobile Chrome
    'Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36'
];

// Função para obter um User-Agent aleatório
function getRandomUserAgent() {
    const randomIndex = Math.floor(Math.random() * FAKE_USER_AGENTS.length);
    return FAKE_USER_AGENTS[randomIndex];
}

// Função para fazer log do referer que seria usado (apenas para debug)
function logSpoofingInfo(url) {
    const referer = getRandomReferrer();
    const userAgent = getRandomUserAgent();
    
    console.log(`🎲 Would use random referer: ${referer}`);
    console.log(`🎭 Would use random user-agent: ${userAgent.substring(0, 50)}...`);
    
    return { referer, userAgent };
}

app.get('/aguarde', async (req, res) => {
    // Página de carregamento primeiro
    const loadingHtml = `
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Redirecionando...</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                background-color: #0f0f0f;
                color: #ffffff;
                min-height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
                padding: 20px;
                overflow: hidden;
            }
            
            .loading-container {
                text-align: center;
                background-color: #1a1a1a;
                padding: 40px 30px;
                border-radius: 16px;
                border: 1px solid #2a2a2a;
                box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
                max-width: 420px;
                width: 100%;
                position: relative;
                overflow: hidden;
            }
            
            .loading-container::before {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                height: 2px;
                background: #4f46e5;
                animation: glow 2s ease-in-out infinite alternate;
            }
            
            @keyframes glow {
                from { opacity: 0.5; }
                to { opacity: 1; }
            }
            
            .spinner {
                width: 60px;
                height: 60px;
                border: 3px solid #2a2a2a;
                border-top: 3px solid #4f46e5;
                border-radius: 50%;
                animation: spin 1s linear infinite;
                margin: 0 auto 30px;
            }
            
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
            
            h1 {
                font-size: 1.8rem;
                font-weight: 600;
                color: #ffffff;
                margin-bottom: 12px;
                line-height: 1.2;
            }
            
            .subtitle {
                font-size: 0.95rem;
                color: #a0a0a0;
                margin-bottom: 30px;
                line-height: 1.4;
            }
            
            .progress-container {
                margin-top: 30px;
            }
            
            .progress-bar {
                width: 100%;
                height: 6px;
                background-color: #2a2a2a;
                border-radius: 3px;
                overflow: hidden;
                margin-bottom: 15px;
            }
            
            .progress {
                height: 100%;
                background-color: #4f46e5;
                width: 0%;
                border-radius: 3px;
                animation: progress 3s ease-out forwards;
                position: relative;
            }
            
            .progress::after {
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                bottom: 0;
                right: 0;
                background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
                animation: shimmer 1.5s infinite;
            }
            
            @keyframes progress {
                0% { width: 0%; }
                100% { width: 100%; }
            }
            
            @keyframes shimmer {
                0% { transform: translateX(-100%); }
                100% { transform: translateX(100%); }
            }
            
            .status-text {
                font-size: 0.85rem;
                color: #6b7280;
                font-weight: 500;
            }
            
            .dots {
                display: inline-block;
            }
            
            .dots::after {
                content: '';
                animation: dots 1.5s steps(4, end) infinite;
            }
            
            @keyframes dots {
                0%, 20% { content: ''; }
                40% { content: '.'; }
                60% { content: '..'; }
                80%, 100% { content: '...'; }
            }
            
            /* Responsividade */
            @media (max-width: 480px) {
                .loading-container {
                    padding: 30px 20px;
                    margin: 10px;
                }
                
                h1 {
                    font-size: 1.5rem;
                }
                
                .subtitle {
                    font-size: 0.9rem;
                }
                
                .spinner {
                    width: 50px;
                    height: 50px;
                    margin-bottom: 25px;
                }
            }
            
            @media (max-width: 320px) {
                .loading-container {
                    padding: 25px 15px;
                }
                
                h1 {
                    font-size: 1.3rem;
                }
                
                .spinner {
                    width: 45px;
                    height: 45px;
                }
            }
            
            /* Modo landscape mobile */
            @media (max-height: 500px) and (orientation: landscape) {
                body {
                    padding: 10px;
                }
                
                .loading-container {
                    padding: 25px 30px;
                }
                
                .spinner {
                    width: 45px;
                    height: 45px;
                    margin-bottom: 20px;
                }
                
                h1 {
                    font-size: 1.4rem;
                    margin-bottom: 8px;
                }
                
                .subtitle {
                    font-size: 0.85rem;
                    margin-bottom: 20px;
                }
                
                .progress-container {
                    margin-top: 20px;
                }
            }
        </style>
    </head>
    <body>
        <div class="loading-container">
            <div class="spinner"></div>
            <h1>Redirecionando</h1>
            <p class="subtitle">Preparando seu acesso ao destino solicitado</p>
            
            <div class="progress-container">
                <div class="progress-bar">
                    <div class="progress"></div>
                </div>
                <div class="status-text">
                    Processando<span class="dots"></span>
                </div>
            </div>
        </div>
        
        <script>
            // Inicia o redirecionamento após 3 segundos
            setTimeout(() => {
                window.location.href = window.location.href + '&process=1';
            }, 3000);
            
            // Adiciona um contador visual opcional
            let seconds = 3;
            const statusText = document.querySelector('.status-text');
            
            const countdown = setInterval(() => {
                seconds--;
                if (seconds > 0) {
                    statusText.innerHTML = \`Redirecionando em \${seconds}s<span class="dots"></span>\`;
                } else {
                    statusText.innerHTML = 'Redirecionando<span class="dots"></span>';
                    clearInterval(countdown);
                }
            }, 1000);
        </script>
    </body>
    </html>
    `;

    // Se não tem o parâmetro process, mostra a página de carregamento
    if (!req.query.process) {
        return res.send(loadingHtml);
    }

    // Agora processa a requisição
    const originalUrl = req.originalUrl;
    const indexOfQuery = originalUrl.indexOf('?a=');
    const encodedUrl = indexOfQuery !== -1 ? decodeURIComponent(originalUrl.substring(indexOfQuery + 3).split('&')[0]) : null;

    if (!encodedUrl) {
        logger.warn('Access to /aguarde without "a" parameter.');
        return res.status(400).send('"a" parameter not found.');
    }

    let targetUrl;
    try {
        targetUrl = Buffer.from(encodedUrl, 'base64').toString('utf8');
        if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
            throw new Error('Invalid URL format.');
        }
    } catch (e) {
        logger.warn(`Invalid Base64 or URL in "a" parameter: ${encodedUrl}`);
        return res.status(400).send('Invalid "a" parameter. Must be a valid Base64 encoded URL.');
    }

    try {
        const serverHost = (req.headers['x-forwarded-host'] || req.headers['host']);
        const target = new URL(targetUrl);

        // Se o destino for o próprio servidor (teste interno)
        if (target.hostname === serverHost && target.pathname === '/check-referer') {
            const spoofInfo = logSpoofingInfo(targetUrl);
            logger.info(`Internal handling for /check-referer with Random Referer: ${spoofInfo.referer}`);
            const userAgent = spoofInfo.userAgent;
            const ip = req.ip;
            const htmlResponse = `
            <!DOCTYPE html>
            <html lang="pt-BR">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Verificador de Referer - Resultado</title>
                <style>
                    body { 
                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                        color: #333; 
                        margin: 0;
                        padding: 20px;
                        min-height: 100vh;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                    }
                    .container { 
                        max-width: 800px; 
                        background: white; 
                        padding: 30px; 
                        border-radius: 15px; 
                        box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                    }
                    h1 { 
                        color: #0056b3; 
                        text-align: center;
                        margin-bottom: 30px;
                        font-size: 2.2em;
                    }
                    .detail { 
                        margin-bottom: 20px; 
                        padding: 15px; 
                        border-left: 4px solid #0056b3; 
                        background-color: #e7f3ff; 
                        word-wrap: break-word;
                        border-radius: 5px;
                    }
                    .detail strong { 
                        color: #004085; 
                        display: block;
                        margin-bottom: 8px;
                        font-size: 1.1em;
                    }
                    .detail p {
                        margin: 0;
                        font-family: monospace;
                        background: rgba(0,0,0,0.05);
                        padding: 8px;
                        border-radius: 3px;
                        font-size: 0.95em;
                    }
                    .success {
                        background-color: #d4edda;
                        border-left-color: #28a745;
                    }
                    .success strong {
                        color: #155724;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>✅ Teste de Referer Spoofing</h1>
                    <div class="detail success">
                        <strong>🎯 Referer Spoofado com Sucesso:</strong>
                        <p>${spoofInfo.referer}</p>
                    </div>
                    <div class="detail">
                        <strong>🔍 User-Agent:</strong>
                        <p>${userAgent}</p>
                    </div>
                    <div class="detail">
                        <strong>📍 IP do Cliente:</strong>
                        <p>${ip}</p>
                    </div>
                    <div class="detail">
                        <strong>⏰ Timestamp:</strong>
                        <p>${new Date().toISOString()}</p>
                    </div>
                </div>
            </body>
            </html>
            `;
            return res.send(htmlResponse);
        }

        // Se for uma URL externa, usa meta refresh com referer spoofing
        const spoofInfo = logSpoofingInfo(targetUrl);
        logger.info(`Meta refresh redirect to: ${targetUrl} with Referer: ${spoofInfo.referer}`);
        
        // Página intermediária com meta refresh e referer spoofing
        const redirectHtml = `
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <meta name="referrer" content="no-referrer">
            <meta http-equiv="refresh" content="0;url=${targetUrl}">
            <title>Redirecionando...</title>
            <style>
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }
                
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    background-color: #0f0f0f;
                    color: #ffffff;
                    min-height: 100vh;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    padding: 20px;
                }
                
                .redirect-container {
                    text-align: center;
                    background-color: #1a1a1a;
                    padding: 40px 30px;
                    border-radius: 16px;
                    border: 1px solid #2a2a2a;
                    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
                    max-width: 420px;
                    width: 100%;
                }
                
                .spinner {
                    width: 40px;
                    height: 40px;
                    border: 3px solid #2a2a2a;
                    border-top: 3px solid #4f46e5;
                    border-radius: 50%;
                    animation: spin 1s linear infinite;
                    margin: 0 auto 20px;
                }
                
                @keyframes spin {
                    0% { transform: rotate(0deg); }
                    100% { transform: rotate(360deg); }
                }
                
                h1 {
                    font-size: 1.5rem;
                    font-weight: 600;
                    color: #ffffff;
                    margin-bottom: 15px;
                }
                
                p {
                    font-size: 0.9rem;
                    color: #a0a0a0;
                    line-height: 1.4;
                }
                
                .fallback-link {
                    display: inline-block;
                    margin-top: 20px;
                    padding: 10px 20px;
                    background-color: #4f46e5;
                    color: white;
                    text-decoration: none;
                    border-radius: 8px;
                    font-size: 0.9rem;
                    transition: background-color 0.3s ease;
                }
                
                .fallback-link:hover {
                    background-color: #3b35d4;
                }
            </style>
        </head>
        <body>
            <div class="redirect-container">
                <div class="spinner"></div>
                <h1>Redirecionando...</h1>
                <p>Se não for redirecionado automaticamente:</p>
                <a href="${targetUrl}" class="fallback-link" rel="noreferrer">Clique aqui</a>
            </div>
            
            <script>
                // Define o referrer via JavaScript antes do redirecionamento
                if (document.referrer !== '${spoofInfo.referer}') {
                    try {
                        // Tenta definir via Object.defineProperty (alguns navegadores)
                        Object.defineProperty(document, 'referrer', {
                            value: '${spoofInfo.referer}',
                            writable: false
                        });
                    } catch(e) {
                        console.log('Referrer spoofing via JS not supported');
                    }
                }
                
                // Fallback para garantir o redirecionamento
                setTimeout(function() {
                    // Cria um link temporário com rel="noreferrer" 
                    const link = document.createElement('a');
                    link.href = '${targetUrl}';
                    link.rel = 'noreferrer';
                    link.target = '_self';
                    link.style.display = 'none';
                    document.body.appendChild(link);
                    link.click();
                }, 100);
            </script>
        </body>
        </html>
        `;
        
        res.send(redirectHtml);

    } catch (error) {
        logger.error('Error in /aguarde endpoint:', { 
            message: error.message,
            code: error.code,
            url: targetUrl
        });
        
        const errorHtml = `
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Erro - LinkGate</title>
            <style>
                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
                    margin: 0;
                    padding: 20px;
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }
                .error-container {
                    background: white;
                    padding: 40px;
                    border-radius: 15px;
                    box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                    text-align: center;
                    max-width: 500px;
                }
                h1 {
                    color: #dc3545;
                    margin-bottom: 20px;
                    font-size: 2em;
                }
                p {
                    color: #666;
                    font-size: 1.1em;
                    line-height: 1.6;
                }
            </style>
        </head>
        <body>
            <div class="error-container">
                <h1>❌ Erro ao Processar</h1>
                <p>Não foi possível acessar o servidor de destino.</p>
                <p>Tente novamente em alguns instantes.</p>
            </div>
        </body>
        </html>
        `;
        
        res.status(502).send(errorHtml);
    }
});

app.get('/check-referer', (req, res) => {
    const referer = req.headers.referer || 'Nenhum referer encontrado.';
    const userAgent = req.headers['user-agent'] || 'Nenhum user-agent encontrado.';
    const ip = req.ip;
    const allHeaders = JSON.stringify(req.headers, null, 2);

    logger.info(`📊 Check referer accessed - Referer: ${referer}, IP: ${ip}, UA: ${userAgent}`);

    const htmlResponse = `
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>🔍 Verificador de Referer - LinkGate</title>
        <style>
            body { 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: #333; 
                margin: 0;
                padding: 20px;
                min-height: 100vh;
            }
            .header {
                text-align: center;
                color: white;
                margin-bottom: 30px;
            }
            .header h1 {
                font-size: 2.5em;
                margin: 0;
                text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
            }
            .header p {
                font-size: 1.2em;
                opacity: 0.9;
                margin: 10px 0;
            }
            .container { 
                max-width: 900px; 
                margin: 0 auto;
                background: white; 
                padding: 30px; 
                border-radius: 15px; 
                box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            }
            .detail { 
                margin-bottom: 25px; 
                padding: 20px; 
                border-radius: 10px;
                word-wrap: break-word;
                transition: transform 0.2s ease;
            }
            .detail:hover {
                transform: translateY(-2px);
            }
            .detail strong { 
                display: block;
                margin-bottom: 10px;
                font-size: 1.2em;
                color: #2c3e50;
            }
            .detail p, .detail pre {
                margin: 0;
                font-family: 'Courier New', monospace;
                background: rgba(0,0,0,0.05);
                padding: 12px;
                border-radius: 5px;
                font-size: 0.95em;
                line-height: 1.4;
                overflow-x: auto;
            }
            .referer {
                background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%);
                border-left: 5px solid #28a745;
            }
            .referer strong {
                color: #155724;
            }
            .user-agent {
                background: linear-gradient(135deg, #e2e3e5 0%, #d6d8db 100%);
                border-left: 5px solid #6c757d;
            }
            .user-agent strong {
                color: #495057;
            }
            .ip {
                background: linear-gradient(135deg, #fff3cd 0%, #ffeaa7 100%);
                border-left: 5px solid #ffc107;
            }
            .ip strong {
                color: #856404;
            }
            .headers {
                background: linear-gradient(135deg, #f8d7da 0%, #f1aeb5 100%);
                border-left: 5px solid #dc3545;
            }
            .headers strong {
                color: #721c24;
            }
            .timestamp {
                background: linear-gradient(135deg, #d1ecf1 0%, #bee5eb 100%);
                border-left: 5px solid #17a2b8;
            }
            .timestamp strong {
                color: #0c5460;
            }
            .test-info {
                background: linear-gradient(135deg, #e7f3ff 0%, #cce7ff 100%);
                border-left: 5px solid #0056b3;
                margin-bottom: 30px;
                text-align: center;
            }
            .test-info strong {
                color: #004085;
            }
            .footer {
                text-align: center;
                margin-top: 30px;
                color: white;
                font-size: 0.9em;
            }
            .copy-btn {
                background: #007bff;
                color: white;
                border: none;
                padding: 5px 10px;
                border-radius: 3px;
                cursor: pointer;
                font-size: 0.8em;
                margin-left: 10px;
            }
            .copy-btn:hover {
                background: #0056b3;
            }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🔍 Verificador de Referer</h1>
            <p>LinkGate API Server - Teste de Spoofing</p>
        </div>
        
        <div class="container">
            <div class="detail test-info">
                <strong>ℹ️ Informações do Teste</strong>
                <p>Este endpoint é usado para verificar se o referer spoofing está funcionando corretamente.</p>
                <p>Acesse via: <code>/aguarde?a=[base64_encoded_url]</code></p>
            </div>
            
            <div class="detail referer">
                <strong>🎯 Referer Detectado:</strong>
                <p>${referer}</p>
                <button class="copy-btn" onclick="copyToClipboard('${referer}')">Copiar</button>
            </div>
            
            <div class="detail user-agent">
                <strong>🔍 User-Agent:</strong>
                <p>${userAgent}</p>
                <button class="copy-btn" onclick="copyToClipboard('${userAgent.replace(/'/g, "\\'")}')">Copiar</button>
            </div>
            
            <div class="detail ip">
                <strong>📍 IP do Cliente:</strong>
                <p>${ip}</p>
                <button class="copy-btn" onclick="copyToClipboard('${ip}')">Copiar</button>
            </div>
            
            <div class="detail timestamp">
                <strong>⏰ Timestamp:</strong>
                <p>${new Date().toISOString()}</p>
                <button class="copy-btn" onclick="copyToClipboard('${new Date().toISOString()}')">Copiar</button>
            </div>
            
            <div class="detail headers">
                <strong>📋 Todos os Headers HTTP:</strong>
                <pre>${allHeaders}</pre>
                <button class="copy-btn" onclick="copyToClipboard(\`${allHeaders.replace(/`/g, '\\`')}\`)">Copiar</button>
            </div>
        </div>
        
        <div class="footer">
            <p>© 2025 LinkGate Redirector - Sistema de Teste de Referer Spoofing</p>
            <p>Desenvolvido para verificação de integridade das requisições</p>
        </div>
        
        <script>
            function copyToClipboard(text) {
                navigator.clipboard.writeText(text).then(function() {
                    alert('Texto copiado para a área de transferência!');
                }).catch(function(err) {
                    console.error('Erro ao copiar texto: ', err);
                });
            }
            
            // Adiciona animação de entrada
            document.addEventListener('DOMContentLoaded', function() {
                const details = document.querySelectorAll('.detail');
                details.forEach((detail, index) => {
                    detail.style.opacity = '0';
                    detail.style.transform = 'translateY(20px)';
                    setTimeout(() => {
                        detail.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
                        detail.style.opacity = '1';
                        detail.style.transform = 'translateY(0)';
                    }, index * 100);
                });
            });
        </script>
    </body>
    </html>
    `;
    res.send(htmlResponse);
});

// Endpoint para gerar URL de teste para o referer spoofing
app.get('/test-referer-generator', (req, res) => {
    const serverHost = req.headers['x-forwarded-host'] || req.headers.host;
    const protocol = req.headers['x-forwarded-proto'] || (req.connection.encrypted ? 'https' : 'http');
    const baseUrl = `${protocol}://${serverHost}`;
    
    const checkRefererUrl = `${baseUrl}/check-referer`;
    const encodedCheckRefererUrl = Buffer.from(checkRefererUrl).toString('base64');
    const testUrl = `${baseUrl}/aguarde?a=${encodedCheckRefererUrl}`;
    
    const generatorHtml = `
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>🧪 Gerador de Teste - LinkGate</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #8B5CF6 0%, #3B82F6 100%);
                margin: 0;
                padding: 20px;
                min-height: 100vh;
                color: white;
            }
            .container {
                max-width: 1000px;
                margin: 0 auto;
                background: rgba(255, 255, 255, 0.95);
                padding: 40px;
                border-radius: 20px;
                box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                color: #333;
            }
            h1 {
                text-align: center;
                color: #8B5CF6;
                font-size: 2.5em;
                margin-bottom: 10px;
            }
            .subtitle {
                text-align: center;
                color: #666;
                font-size: 1.2em;
                margin-bottom: 40px;
            }
            .section {
                background: #f8f9fa;
                padding: 25px;
                border-radius: 12px;
                margin-bottom: 25px;
                border-left: 5px solid #8B5CF6;
            }
            .section h3 {
                color: #8B5CF6;
                margin-bottom: 15px;
                font-size: 1.4em;
            }
            .url-box {
                background: white;
                padding: 15px;
                border-radius: 8px;
                border: 2px solid #e9ecef;
                font-family: monospace;
                font-size: 0.9em;
                word-break: break-all;
                margin: 10px 0;
                position: relative;
            }
            .copy-btn {
                background: #8B5CF6;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                cursor: pointer;
                font-size: 0.9em;
                margin: 10px 5px 0 0;
                transition: background 0.3s ease;
            }
            .copy-btn:hover {
                background: #7C3AED;
            }
            .test-btn {
                background: #10B981;
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 8px;
                cursor: pointer;
                font-size: 1em;
                margin: 10px 5px 0 0;
                text-decoration: none;
                display: inline-block;
                transition: background 0.3s ease;
            }
            .test-btn:hover {
                background: #059669;
            }
            .warning {
                background: #FEF3C7;
                border: 1px solid #F59E0B;
                border-radius: 8px;
                padding: 15px;
                margin: 20px 0;
                color: #92400E;
            }
            .warning strong {
                color: #D97706;
            }
            .custom-url {
                width: 100%;
                padding: 12px;
                border: 2px solid #e9ecef;
                border-radius: 8px;
                font-size: 1em;
                margin: 10px 0;
            }
            .custom-url:focus {
                border-color: #8B5CF6;
                outline: none;
            }
            .generate-btn {
                background: #3B82F6;
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 8px;
                cursor: pointer;
                font-size: 1em;
                margin: 10px 0;
                width: 100%;
            }
            .generate-btn:hover {
                background: #2563EB;
            }
            .result {
                display: none;
                background: #ECFDF5;
                border: 1px solid #10B981;
                border-radius: 8px;
                padding: 15px;
                margin: 20px 0;
                color: #065F46;
            }
            .info-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 20px;
                margin-top: 30px;
            }
            .info-card {
                background: white;
                padding: 20px;
                border-radius: 12px;
                border: 1px solid #e9ecef;
                box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            }
            .info-card h4 {
                color: #8B5CF6;
                margin-bottom: 10px;
                font-size: 1.2em;
            }
            .info-card p {
                color: #666;
                line-height: 1.6;
                margin: 8px 0;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🧪 Gerador de Teste de Referer Spoofing</h1>
            <p class="subtitle">LinkGate API Server - Ferramenta de Teste e Validação</p>
            
            <div class="section">
                <h3>🎯 Teste Automático (Recomendado)</h3>
                <p>Este teste usa o endpoint /check-referer interno para verificar se o spoofing está funcionando:</p>
                
                <div class="url-box">${testUrl}</div>
                
                <button class="copy-btn" onclick="copyToClipboard('${testUrl}')">📋 Copiar URL</button>
                <a href="${testUrl}" target="_blank" class="test-btn">🚀 Testar Agora</a>
                
                <div class="warning">
                    <strong>⚠️ Como funciona:</strong><br>
                    1. Clique em "Testar Agora" ou cole a URL no navegador<br>
                    2. Você verá uma página de carregamento por 3 segundos<br>
                    3. Meta refresh redirecionará para o destino com referer spoofado<br>
                    4. Para teste interno: use /check-referer para verificar o referer real
                </div>
            </div>
            
            <div class="section">
                <h3>🔧 Teste Personalizado</h3>
                <p>Insira qualquer URL para testar o referer spoofing com sites externos:</p>
                
                <input type="url" id="customUrl" class="custom-url" placeholder="https://exemplo.com" value="">
                <button class="generate-btn" onclick="generateCustomTest()">🔗 Gerar URL de Teste</button>
                
                <div id="customResult" class="result">
                    <strong>✅ URL de teste gerada com sucesso!</strong><br>
                    <div id="customTestUrl" class="url-box"></div>
                    <button class="copy-btn" onclick="copyCustomUrl()">📋 Copiar</button>
                    <button class="test-btn" onclick="testCustomUrl()">🚀 Testar</button>
                </div>
            </div>
            
            <div class="info-grid">
                <div class="info-card">
                    <h4>📊 Como Interpretar os Resultados</h4>
                    <p><strong>Referer Spoofado:</strong> Se aparecer "https://fakereferer.org", o spoofing funcionou!</p>
                    <p><strong>Headers HTTP:</strong> Verifique todos os cabeçalhos enviados na requisição.</p>
                    <p><strong>User-Agent:</strong> Mostra o navegador/ferramenta que fez a requisição.</p>
                </div>
                
                <div class="info-card">
                    <h4>🔍 Endpoints Disponíveis</h4>
                    <p><strong>/aguarde:</strong> Endpoint principal com referer spoofing</p>
                    <p><strong>/check-referer:</strong> Página de teste para verificar headers</p>
                    <p><strong>/health:</strong> Status do servidor API</p>
                </div>
                
                <div class="info-card">
                    <h4>⚙️ Configurações Técnicas</h4>
                    <p><strong>Redirecionamento:</strong> Meta refresh com referer spoofing</p>
                    <p><strong>Timeout:</strong> 3 segundos na página de carregamento</p>
                    <p><strong>Encoding:</strong> URLs são codificadas em Base64</p>
                    <p><strong>Referrers:</strong> Google, Facebook, YouTube, Instagram, X.com</p>
                </div>
                
                <div class="info-card">
                    <h4>🎨 Recursos da Interface</h4>
                    <p><strong>Página de Carregamento:</strong> Design moderno com animações</p>
                    <p><strong>Responsive:</strong> Funciona em desktop e mobile</p>
                    <p><strong>Logs Detalhados:</strong> Todas as requisições são logadas</p>
                </div>
            </div>
        </div>
        
        <script>
            let customTestUrl = '';
            
            function copyToClipboard(text) {
                navigator.clipboard.writeText(text).then(function() {
                    alert('✅ URL copiada para a área de transferência!');
                }).catch(function(err) {
                    console.error('❌ Erro ao copiar:', err);
                    // Fallback para navegadores mais antigos
                    const textArea = document.createElement('textarea');
                    textArea.value = text;
                    document.body.appendChild(textArea);
                    textArea.select();
                    document.execCommand('copy');
                    document.body.removeChild(textArea);
                    alert('✅ URL copiada!');
                });
            }
            
            function generateCustomTest() {
                const customUrl = document.getElementById('customUrl').value;
                if (!customUrl) {
                    alert('⚠️ Por favor, insira uma URL válida!');
                    return;
                }
                
                try {
                    new URL(customUrl); // Valida se é uma URL válida
                    const encodedUrl = btoa(customUrl);
                    customTestUrl = '${baseUrl}/aguarde?a=' + encodedUrl;
                    
                    document.getElementById('customTestUrl').textContent = customTestUrl;
                    document.getElementById('customResult').style.display = 'block';
                } catch (e) {
                    alert('❌ URL inválida! Por favor, insira uma URL completa (ex: https://exemplo.com)');
                }
            }
            
            function copyCustomUrl() {
                copyToClipboard(customTestUrl);
            }
            
            function testCustomUrl() {
                if (customTestUrl) {
                    window.open(customTestUrl, '_blank');
                }
            }
            
            // Auto-focus no campo de URL personalizada
            document.addEventListener('DOMContentLoaded', function() {
                document.getElementById('customUrl').focus();
            });
        </script>
    </body>
    </html>
    `;
    
    res.send(generatorHtml);
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