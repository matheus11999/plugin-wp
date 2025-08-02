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
const { exec } = require('child_process');
const { promisify } = require('util');
const execAsync = promisify(exec);
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


// Configurações do sistema
const CONFIG = {
    // Domínios ativos para redirecionamento via proxy
    ACTIVE_DOMAINS: [
        'https://evoapi-wp.ttvjwi.easypanel.host'  // Domínio ativo com endpoint redirect.php
    ],
    
    // Delay da página de wait antes do redirecionamento (em segundos)
    WAIT_DELAY_SECONDS: 3,
    
    // Headers customizados para proxy
    PROXY_HEADERS: {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'pt-BR,pt;q=0.9,en;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    }
};

// Lista expandida de referrers para spoofing mais efetivo
const FAKE_REFERRERS = [
    // Google (maior gerador de tráfego)
    'https://www.google.com/search?q=',
    'https://www.google.com.br/search?q=',
    'https://www.google.com/',
    'https://images.google.com/',
    'https://news.google.com/',
    
    // Facebook (segundo maior)
    'https://www.facebook.com/',
    'https://m.facebook.com/',
    'https://www.facebook.com/l.php?u=',
    'https://l.facebook.com/l.php?u=',
    
    // YouTube (terceiro maior)
    'https://www.youtube.com/',
    'https://m.youtube.com/',
    'https://www.youtube.com/watch?v=',
    
    // Instagram (quarto maior)
    'https://www.instagram.com/',
    'https://www.instagram.com/explore/',
    
    // X/Twitter (quinto maior)
    'https://x.com/',
    'https://twitter.com/',
    'https://t.co/',
    
    // Outras fontes importantes
    'https://www.reddit.com/',
    'https://www.reddit.com/r/all',
    'https://www.linkedin.com/',
    'https://duckduckgo.com/',
    'https://www.bing.com/',
    'https://search.yahoo.com/',
    'https://www.pinterest.com/',
    'https://www.tiktok.com/',
    'https://www.baidu.com/',
    'https://yandex.com/',
    'https://www.wikipedia.org/',
    'https://github.com/',
    'https://stackoverflow.com/',
    'https://medium.com/',
    'https://www.quora.com/'
];

// Função para obter um referrer aleatório com variações realistas
function getRandomReferrer() {
    const randomIndex = Math.floor(Math.random() * FAKE_REFERRERS.length);
    const baseReferrer = FAKE_REFERRERS[randomIndex];
    
    // Se for um referrer de busca, adiciona um termo aleatório
    if (baseReferrer.includes('?q=') && baseReferrer.endsWith('?q=')) {
        const searchTerms = [
            'url shortener', 'link redirect', 'online tools', 'web utilities',
            'link generator', 'redirect service', 'url tools', 'web apps',
            'link manager', 'redirect links', 'short urls', 'link sharing',
            'technology news', 'best practices', 'tutorial guide', 'how to',
            'latest updates', 'programming tips', 'web development', 'digital tools'
        ];
        const randomTerm = searchTerms[Math.floor(Math.random() * searchTerms.length)];
        return baseReferrer + encodeURIComponent(randomTerm);
    }
    
    // Para YouTube, adicionar parâmetros realistas
    if (baseReferrer.includes('youtube.com/watch?v=')) {
        const videoIds = ['dQw4w9WgXcQ', 'jNQXAC9IVRw', 'ZZ5LpwO-An4', 'fJ9rUzIMcZQ', 'y6120QOlsfU'];
        const randomId = videoIds[Math.floor(Math.random() * videoIds.length)];
        return baseReferrer + randomId;
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

// Função para obter um domínio ativo aleatório
function getRandomActiveDomain() {
    const randomIndex = Math.floor(Math.random() * CONFIG.ACTIVE_DOMAINS.length);
    return CONFIG.ACTIVE_DOMAINS[randomIndex];
}

// Função para fazer requisição com cURL e referer spoofing REAL (para testes)
async function fetchWithCurlSpoof(url) {
    const referer = getRandomReferrer();
    const userAgent = getRandomUserAgent();
    
    console.log(`🎲 Using random referer: ${referer}`);
    console.log(`🎭 Using random user-agent: ${userAgent.substring(0, 50)}...`);
    
    try {
        const curlCommand = `curl -s -L -I --max-redirs 5 --referer "${referer}" --user-agent "${userAgent}" "${url}"`;
        const { stdout, stderr } = await execAsync(curlCommand);
        
        if (stderr) {
            console.log(`⚠️ cURL stderr: ${stderr}`);
        }
        
        console.log(`✅ cURL request sent with spoofed referer: ${referer}`);
        return { success: true, referer, userAgent, headers: stdout };
    } catch (error) {
        console.log(`💥 cURL error: ${error.message}`);
        throw error;
    }
}

// Função para extrair cookies de resposta HTTP headers
function extractCookiesFromHeaders(headers) {
    const cookies = [];
    const setCookieHeaders = headers.match(/Set-Cookie: ([^\r\n]+)/gi);
    
    if (setCookieHeaders) {
        setCookieHeaders.forEach(header => {
            const cookieValue = header.replace(/Set-Cookie: /i, '').split(';')[0];
            cookies.push(cookieValue);
        });
    }
    
    return cookies.join('; ');
}

// Função para fazer proxy transparente com referer spoofing e gerenciamento de sessões PHP
async function fetchProxyWithSpoof(url, userAgent = null, cookies = null, includeHeaders = false) {
    const referer = getRandomReferrer();
    const finalUserAgent = userAgent || getRandomUserAgent();
    
    console.log(`🎯 Proxy request to: ${url}`);
    console.log(`🎲 Using spoofed referer: ${referer}`);
    console.log(`🎭 Using user-agent: ${finalUserAgent.substring(0, 50)}...`);
    
    try {
        // Construir comando cURL com suporte completo para sessões PHP e descompressão automática
        let curlCommand = `curl -s -L --max-redirs 5 --referer "${referer}" --user-agent "${finalUserAgent}"`;
        
        // IMPORTANTE: Adicionar --compressed para descomprimir gzip/deflate automaticamente
        curlCommand += ` --compressed`;
        
        // Incluir headers se solicitado (para capturar Set-Cookie)
        if (includeHeaders) {
            curlCommand += ` -i`;
        }
        
        // Adicionar cookies se fornecidos (para manter sessões PHP/WordPress)
        if (cookies) {
            console.log(`🍪 Using cookies for session: ${cookies.substring(0, 100)}...`);
            curlCommand += ` --cookie "${cookies}"`;
        }
        
        // Headers para simular navegador real
        curlCommand += ` -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"`;
        curlCommand += ` -H "Accept-Language: pt-BR,pt;q=0.9,en;q=0.8"`;
        curlCommand += ` -H "Accept-Encoding: gzip, deflate, br"`;
        curlCommand += ` -H "Connection: keep-alive"`;
        curlCommand += ` -H "Upgrade-Insecure-Requests: 1"`;
        curlCommand += ` -H "Sec-Fetch-Dest: document"`;
        curlCommand += ` -H "Sec-Fetch-Mode: navigate"`;
        curlCommand += ` -H "Sec-Fetch-Site: none"`;
        curlCommand += ` -H "Cache-Control: max-age=0"`;
        
        curlCommand += ` "${url}"`;
        
        console.log(`🔧 cURL command: ${curlCommand.substring(0, 300)}...`);
        
        const { stdout, stderr } = await execAsync(curlCommand);
        
        if (stderr) {
            console.log(`⚠️ cURL stderr: ${stderr}`);
        }
        
        console.log(`✅ Proxy request successful with spoofed referer: ${referer}`);
        console.log(`📏 Response length: ${stdout.length} characters`);
        
        let responseHeaders = '';
        let responseBody = stdout;
        
        // Se incluiu headers, separar headers do body
        if (includeHeaders && stdout.includes('\r\n\r\n')) {
            const parts = stdout.split('\r\n\r\n');
            responseHeaders = parts[0];
            responseBody = parts.slice(1).join('\r\n\r\n');
            
            console.log(`📋 Response headers captured: ${responseHeaders.length} chars`);
        }
        
        // Verificar se o conteúdo parece estar comprimido (dados binários)
        const isBinaryContent = responseBody.length > 100 && 
                               (responseBody.includes('�') || 
                                responseBody.charCodeAt(0) === 31 || // gzip magic number
                                responseBody.charCodeAt(1) === 139);
        
        if (isBinaryContent && !includeHeaders) {
            console.log(`⚠️ Content appears to be compressed despite --compressed flag`);
            console.log(`🔧 Content preview (first 50 chars): ${responseBody.substring(0, 50)}`);
        } else {
            console.log(`✅ Content appears to be properly decompressed`);
            console.log(`📄 Content preview: ${responseBody.substring(0, 200)}...`);
        }
        
        return { 
            success: true, 
            content: responseBody,
            headers: responseHeaders,
            referer, 
            userAgent: finalUserAgent 
        };
    } catch (error) {
        console.log(`💥 Proxy cURL error: ${error.message}`);
        throw error;
    }
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
    const encodedUrl = req.query.a;
    
    if (!encodedUrl) {
        logger.warn('Access to /aguarde without "a" parameter.');
        return res.status(400).send(`
            <!DOCTYPE html>
            <html lang="pt-BR">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Erro - Parâmetro Obrigatório</title>
                <style>
                    body { font-family: Arial, sans-serif; background: #0f0f0f; color: #fff; text-align: center; padding: 50px; }
                    .error { background: #ff4444; padding: 20px; border-radius: 10px; display: inline-block; }
                </style>
            </head>
            <body>
                <div class="error">
                    <h1>❌ Erro</h1>
                    <p>Parâmetro "a" (URL codificada em Base64) é obrigatório.</p>
                    <p>Formato: /aguarde?a=[base64_url]</p>
                </div>
            </body>
            </html>
        `);
    }

    // Página de aguarde simples - preta com progress bar
    const waitPageHtml = `
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta name="robots" content="noindex, nofollow">
        <meta name="referrer" content="no-referrer">
        <title>Aguarde</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: Arial, sans-serif;
                background: #000000;
                color: #ffffff;
                min-height: 100vh;
                display: flex;
                flex-direction: column;
                justify-content: center;
                align-items: center;
                padding: 20px;
            }
            
            .container {
                text-align: center;
                max-width: 400px;
                width: 100%;
            }
            
            h1 {
                font-size: 2rem;
                font-weight: normal;
                margin-bottom: 40px;
                letter-spacing: 2px;
            }
            
            .progress-bar {
                width: 100%;
                height: 8px;
                background: #333333;
                border-radius: 4px;
                overflow: hidden;
                margin-bottom: 20px;
            }
            
            .progress-fill {
                height: 100%;
                background: #ffffff;
                border-radius: 4px;
                width: 0%;
                animation: fillProgress 3s ease-in-out forwards;
            }
            
            @keyframes fillProgress {
                0% { width: 0%; }
                100% { width: 100%; }
            }
            
            @media (max-width: 480px) {
                h1 { font-size: 1.5rem; }
                .container { padding: 20px; }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Aguarde</h1>
            
            <div class="progress-bar">
                <div class="progress-fill"></div>
            </div>
        </div>
        
        <script>
            // Sistema simples de redirecionamento
            const urlParam = new URL(window.location.href).searchParams.get('a');
            
            if (urlParam) {
                setTimeout(() => {
                    try {
                        const targetUrl = atob(urlParam);
                        const currentDomain = window.location.protocol + '//' + window.location.host;
                        const encodedTargetUrl = btoa(targetUrl);
                        const proxyUrl = currentDomain + '/redirect?url=' + encodedTargetUrl;
                        window.location.href = proxyUrl;
                    } catch (e) {
                        console.error('Erro ao decodificar URL:', e);
                    }
                }, ${CONFIG.WAIT_DELAY_SECONDS * 1000});
            }
        </script>
    </body>
    </html>
    `;

    // Retornar a página de wait
    logger.info(`📄 Displaying wait page for URL parameter: ${encodedUrl.substring(0, 50)}...`);
    console.log(`⏱️ Wait page shown, user will be redirected in ${CONFIG.WAIT_DELAY_SECONDS} seconds`);
    res.send(waitPageHtml);
});

// Endpoint para proxy transparente real (/redirect?url=[base64])
app.get('/redirect', async (req, res) => {
    const encodedUrl = req.query.url;
    const requestId = req.id;
    
    console.log(`🔄 [${requestId}] Transparent proxy request received: ${encodedUrl?.substring(0, 50)}...`);
    
    if (!encodedUrl) {
        logger.warn(`Access to /redirect without URL parameter from ${req.ip}`);
        return res.status(400).send(`
            <!DOCTYPE html>
            <html lang="pt-BR">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Erro - Parâmetro Obrigatório</title>
                <style>
                    body { 
                        font-family: Arial, sans-serif; 
                        background: #0f0f0f; 
                        color: #fff; 
                        text-align: center; 
                        padding: 50px; 
                        min-height: 100vh;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                    }
                    .error { 
                        background: #ff4444; 
                        padding: 30px; 
                        border-radius: 10px; 
                        display: inline-block;
                        max-width: 500px;
                    }
                </style>
            </head>
            <body>
                <div class="error">
                    <h1>❌ Erro</h1>
                    <p>Parâmetro "url" (URL codificada em Base64) é obrigatório.</p>
                    <p>Formato: /redirect?url=[base64_url]</p>
                </div>
            </body>
            </html>
        `);
    }

    // Decodificar URL de destino
    let targetUrl;
    try {
        targetUrl = Buffer.from(encodedUrl, 'base64').toString('utf8');
        
        // Validar se é uma URL válida
        const urlObj = new URL(targetUrl);
        if (!['http:', 'https:'].includes(urlObj.protocol)) {
            throw new Error('Protocolo não suportado');
        }
        
        console.log(`🎯 [${requestId}] Target URL: ${targetUrl}`);
        
    } catch (error) {
        logger.warn(`Invalid URL decoding for request ${requestId}: ${error.message}`);
        return res.status(400).send(`
            <!DOCTYPE html>
            <html lang="pt-BR">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Erro - URL Inválida</title>
                <style>
                    body { 
                        font-family: Arial, sans-serif; 
                        background: #0f0f0f; 
                        color: #fff; 
                        text-align: center; 
                        padding: 50px; 
                        min-height: 100vh;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                    }
                    .error { 
                        background: #ff4444; 
                        padding: 30px; 
                        border-radius: 10px; 
                        display: inline-block;
                        max-width: 500px;
                    }
                </style>
            </head>
            <body>
                <div class="error">
                    <h1>❌ URL Inválida</h1>
                    <p>Não foi possível decodificar a URL fornecida.</p>
                    <p>Erro: ${error.message}</p>
                </div>
            </body>
            </html>
        `);
    }

    try {
        // Selecionar domínio ativo aleatório
        const activeDomain = getRandomActiveDomain();
        console.log(`🌐 [${requestId}] Selected active domain: ${activeDomain}`);
        
        // Construir URL do proxy no domínio ativo
        const proxyUrl = `${activeDomain}/redirect.php?url=${encodedUrl}`;
        console.log(`🎯 [${requestId}] Proxy URL: ${proxyUrl}`);
        
        // Gerar referer e user-agent falsos
        const fakeReferer = getRandomReferrer();
        const fakeUserAgent = req.headers['user-agent'] || getRandomUserAgent();
        
        // Capturar cookies do usuário para manter sessões do WordPress
        const userCookies = req.headers.cookie;
        
        console.log(`🎲 [${requestId}] Using spoofed referer: ${fakeReferer}`);
        console.log(`🎭 [${requestId}] Using user-agent: ${fakeUserAgent.substring(0, 50)}...`);
        console.log(`🍪 [${requestId}] User cookies: ${userCookies ? userCookies.substring(0, 100) + '...' : 'None'}`);
        
        // Fazer requisição proxy transparente para o domínio ativo
        logger.info(`Starting transparent proxy for ${requestId}`, {
            targetUrl,
            proxyUrl,
            activeDomain,
            clientIP: req.ip,
            spoofedReferer: fakeReferer,
            userAgent: fakeUserAgent,
            hasCookies: !!userCookies
        });
        
        // Etapa 1: Capturar headers/cookies com requisição HEAD/GET para estabelecer sessão
        console.log(`🔗 [${requestId}] Step 1: Establishing PHP session and capturing cookies`);
        const headerResult = await fetchProxyWithSpoof(proxyUrl, fakeUserAgent, null, true);
        
        // Extrair cookies de sessão da resposta
        const sessionCookies = extractCookiesFromHeaders(headerResult.headers);
        console.log(`🍪 [${requestId}] Session cookies extracted: ${sessionCookies || 'None'}`);
        
        // Log específico para PHPSESSID
        if (sessionCookies && sessionCookies.includes('PHPSESSID')) {
            console.log(`✅ [${requestId}] PHP Session ID found in cookies - session established`);
        } else {
            console.log(`⚠️ [${requestId}] No PHP Session ID found - may affect session continuity`);
        }
        
        // Etapa 2: Fazer requisição com cookies para obter conteúdo descomprimido
        console.log(`🔄 [${requestId}] Step 2: Fetching decompressed content with session cookies`);
        
        // Aguardar um momento para simular comportamento humano
        await new Promise(resolve => setTimeout(resolve, 500));
        
        // Requisição final com cookies de sessão e descompressão adequada
        let finalResult;
        if (sessionCookies) {
            finalResult = await fetchProxyWithSpoof(proxyUrl, fakeUserAgent, sessionCookies, false);
            console.log(`✅ [${requestId}] Session-aware request with decompression completed`);
        } else {
            // Se não tem cookies, fazer requisição simples descomprimida
            finalResult = await fetchProxyWithSpoof(proxyUrl, fakeUserAgent, null, false);
            console.log(`⚠️ [${requestId}] No session cookies, using simple decompressed request`);
        }
        
        const proxyResult = finalResult;
        
        console.log(`✅ [${requestId}] Proxy request successful through active domain`);
        console.log(`🎲 [${requestId}] Final spoofed referer used: ${proxyResult.referer}`);
        console.log(`🔍 [${requestId}] Response contains referer verification: ${proxyResult.content.includes('referer') || proxyResult.content.includes('Referer')}`);
        
        // Log para verificar se o referer foi aceito pelo sistema remoto
        if (proxyResult.content.includes('google.com') || proxyResult.content.includes('facebook.com') || 
            proxyResult.content.includes('youtube.com') || proxyResult.content.includes('instagram.com')) {
            console.log(`✅ [${requestId}] Referer spoofing appears successful - response contains expected referrer domains`);
        }
        
        // Detectar content-type baseado no conteúdo
        let contentType = 'text/html; charset=utf-8';
        const trimmedContent = proxyResult.content.trim();
        
        // Detectar JSON
        if (trimmedContent.startsWith('{') && trimmedContent.endsWith('}')) {
            contentType = 'application/json; charset=utf-8';
        } 
        // Detectar XML
        else if (trimmedContent.startsWith('<?xml') || trimmedContent.startsWith('<xml')) {
            contentType = 'text/xml; charset=utf-8';
        }
        // Detectar JavaScript
        else if (targetUrl.includes('.js') || trimmedContent.includes('function') || trimmedContent.includes('var ')) {
            contentType = 'application/javascript; charset=utf-8';
        }
        // Detectar CSS
        else if (targetUrl.includes('.css') || trimmedContent.includes('{') && trimmedContent.includes('}')) {
            contentType = 'text/css; charset=utf-8';
        }
        // Default para HTML
        else {
            contentType = 'text/html; charset=utf-8';
        }
        
        // Corrigir content-type baseado no conteúdo real
        let finalContentType = 'text/html; charset=utf-8';
        const content = proxyResult.content.trim();
        
        // Se o conteúdo parece ser HTML, forçar content-type correto
        if (content.toLowerCase().includes('<!doctype html') || 
            content.toLowerCase().includes('<html') || 
            content.toLowerCase().includes('<head') ||
            content.toLowerCase().includes('<body')) {
            finalContentType = 'text/html; charset=utf-8';
        }
        
        // Headers para proxy transparente
        res.setHeader('Content-Type', finalContentType);
        res.setHeader('X-Spoofed-Referer', proxyResult.referer);
        res.setHeader('X-Original-Target', targetUrl);
        res.setHeader('X-Proxy-Through', proxyUrl);
        res.setHeader('X-Active-Domain', activeDomain);
        res.setHeader('X-Proxy-By', 'LinkGate-Redirector');
        res.setHeader('X-Request-ID', requestId);
        
        // Remover/relaxar Content Security Policy para permitir recursos externos
        res.setHeader('Content-Security-Policy', 
            "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:; " +
            "script-src * 'unsafe-inline' 'unsafe-eval'; " +
            "style-src * 'unsafe-inline'; " +
            "img-src * data: blob:; " +
            "font-src * data:; " +
            "connect-src * 'unsafe-inline'; " +
            "frame-src * 'unsafe-inline'"
        );
        
        // Prevenir cache do browser
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
        
        // Processar conteúdo HTML para corrigir URLs e links
        let processedContent = proxyResult.content;
        
        // Se for HTML, reescrever URLs relativos para absolutos
        if (finalContentType.includes('text/html')) {
            const activeDomainUrl = new URL(activeDomain);
            const baseUrl = `${activeDomainUrl.protocol}//${activeDomainUrl.host}`;
            
            // Corrigir URLs relativos em recursos (CSS, JS, imagens)
            processedContent = processedContent
                .replace(/href="\/([^"]*?)"/g, `href="${baseUrl}/$1"`)
                .replace(/src="\/([^"]*?)"/g, `src="${baseUrl}/$1"`)
                .replace(/action="\/([^"]*?)"/g, `action="${baseUrl}/$1"`)
                .replace(/url\(\/([^)]*?)\)/g, `url(${baseUrl}/$1)`);
            
            // Adicionar base tag para URLs relativos
            if (processedContent.includes('<head>')) {
                processedContent = processedContent.replace(
                    '<head>', 
                    `<head>\n<base href="${baseUrl}/">\n`
                );
            }
            
            console.log(`🔧 [${requestId}] HTML content processed - URLs rewritten to absolute`);
        }
        
        console.log(`📤 [${requestId}] Sending content (${processedContent.length} bytes, ${finalContentType})`);
        
        // Retornar o conteúdo processado
        res.status(200).send(processedContent);
        
    } catch (error) {
        console.error(`❌ [${requestId}] Transparent proxy failed:`, error);
        logger.error(`Transparent proxy error for ${requestId}:`, {
            error: error.message,
            stack: error.stack,
            targetUrl,
            clientIP: req.ip
        });
        
        // Página de erro em caso de falha no proxy
        const errorHtml = `
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Erro no Proxy Transparente</title>
            <style>
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: #ffffff;
                    min-height: 100vh;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    margin: 0;
                    padding: 20px;
                }
                .error-container {
                    background: rgba(255, 255, 255, 0.1);
                    backdrop-filter: blur(10px);
                    padding: 40px;
                    border-radius: 20px;
                    border: 1px solid rgba(255, 255, 255, 0.2);
                    text-align: center;
                    max-width: 500px;
                    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.2);
                }
                h1 {
                    color: #ff6b6b;
                    margin-bottom: 20px;
                    font-size: 2em;
                }
                p {
                    margin-bottom: 15px;
                    line-height: 1.6;
                    opacity: 0.9;
                }
                .error-detail {
                    background: rgba(255, 107, 107, 0.1);
                    padding: 15px;
                    border-radius: 10px;
                    margin: 20px 0;
                    border-left: 4px solid #ff6b6b;
                    text-align: left;
                }
                code {
                    background: rgba(0, 0, 0, 0.2);
                    padding: 2px 6px;
                    border-radius: 4px;
                    font-family: monospace;
                    font-size: 0.9em;
                    word-break: break-all;
                }
                .btn {
                    background: linear-gradient(135deg, #4f46e5, #7c3aed);
                    color: white;
                    border: none;
                    padding: 12px 24px;
                    border-radius: 8px;
                    cursor: pointer;
                    text-decoration: none;
                    display: inline-block;
                    margin-top: 20px;
                    transition: transform 0.2s ease;
                }
                .btn:hover {
                    transform: translateY(-2px);
                }
            </style>
        </head>
        <body>
            <div class="error-container">
                <h1>❌ Erro no Proxy Transparente</h1>
                <p>Não foi possível acessar o conteúdo através do proxy transparente.</p>
                <div class="error-detail">
                    <strong>URL de Destino:</strong><br>
                    <code>${targetUrl}</code>
                </div>
                <div class="error-detail">
                    <strong>Erro:</strong><br>
                    <code>${error.message}</code>
                </div>
                <div class="error-detail">
                    <strong>Request ID:</strong><br>
                    <code>${requestId}</code>
                </div>
                <button onclick="window.history.back()" class="btn">🔙 Voltar</button>
            </div>
        </body>
        </html>
        `;
        
        res.status(502).send(errorHtml);
    }
});

// Endpoint para testar o novo sistema de proxy
app.get('/test-proxy-system', (req, res) => {
    const serverHost = req.headers['x-forwarded-host'] || req.headers.host;
    const protocol = req.headers['x-forwarded-proto'] || (req.connection.encrypted ? 'https' : 'http');
    const baseUrl = `${protocol}://${serverHost}`;
    
    // URLs de teste
    const testUrls = [
        'https://google.com',
        'https://example.com', 
        'https://httpbin.org/headers',
        `${baseUrl}/check-referer`
    ];
    
    const testPageHtml = `
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>🧪 Teste do Sistema de Proxy - LinkGate</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 20px;
                color: white;
            }
            
            .container {
                max-width: 1000px;
                margin: 0 auto;
                background: rgba(255, 255, 255, 0.1);
                backdrop-filter: blur(10px);
                border-radius: 20px;
                padding: 40px;
                box-shadow: 0 20px 60px rgba(0, 0, 0, 0.2);
                border: 1px solid rgba(255, 255, 255, 0.2);
            }
            
            h1 {
                text-align: center;
                font-size: 2.5em;
                margin-bottom: 10px;
                text-shadow: 0 2px 10px rgba(0, 0, 0, 0.3);
            }
            
            .subtitle {
                text-align: center;
                font-size: 1.2em;
                margin-bottom: 40px;
                opacity: 0.9;
            }
            
            .section {
                background: rgba(255, 255, 255, 0.1);
                border-radius: 15px;
                padding: 25px;
                margin-bottom: 25px;
                border: 1px solid rgba(255, 255, 255, 0.2);
            }
            
            .section h3 {
                color: #ffffff;
                margin-bottom: 15px;
                font-size: 1.4em;
            }
            
            .test-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 20px;
                margin-top: 20px;
            }
            
            .test-card {
                background: rgba(255, 255, 255, 0.1);
                border-radius: 12px;
                padding: 20px;
                border: 1px solid rgba(255, 255, 255, 0.2);
                transition: transform 0.3s ease, box-shadow 0.3s ease;
            }
            
            .test-card:hover {
                transform: translateY(-5px);
                box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
            }
            
            .test-card h4 {
                color: #ffffff;
                margin-bottom: 10px;
                font-size: 1.2em;
            }
            
            .test-card p {
                color: rgba(255, 255, 255, 0.8);
                margin-bottom: 15px;
                line-height: 1.5;
            }
            
            .test-url {
                background: rgba(0, 0, 0, 0.3);
                padding: 10px;
                border-radius: 8px;
                font-family: monospace;
                font-size: 0.9em;
                word-break: break-all;
                margin: 10px 0;
                border: 1px solid rgba(255, 255, 255, 0.1);
            }
            
            .btn {
                background: linear-gradient(135deg, #4f46e5, #7c3aed);
                color: white;
                border: none;
                padding: 12px 24px;
                border-radius: 8px;
                cursor: pointer;
                font-size: 1em;
                margin: 5px;
                text-decoration: none;
                display: inline-block;
                transition: all 0.3s ease;
                box-shadow: 0 4px 15px rgba(79, 70, 229, 0.3);
            }
            
            .btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 6px 20px rgba(79, 70, 229, 0.4);
            }
            
            .btn-copy {
                background: linear-gradient(135deg, #10b981, #059669);
                box-shadow: 0 4px 15px rgba(16, 185, 129, 0.3);
            }
            
            .btn-copy:hover {
                box-shadow: 0 6px 20px rgba(16, 185, 129, 0.4);
            }
            
            .custom-test {
                background: rgba(255, 255, 255, 0.1);
                border-radius: 15px;
                padding: 25px;
                margin-top: 30px;
                border: 1px solid rgba(255, 255, 255, 0.2);
            }
            
            .custom-url {
                width: 100%;
                padding: 15px;
                border: 2px solid rgba(255, 255, 255, 0.2);
                border-radius: 10px;
                background: rgba(255, 255, 255, 0.1);
                color: white;
                font-size: 1em;
                margin: 10px 0;
                backdrop-filter: blur(5px);
            }
            
            .custom-url::placeholder {
                color: rgba(255, 255, 255, 0.6);
            }
            
            .custom-url:focus {
                outline: none;
                border-color: #4f46e5;
                box-shadow: 0 0 20px rgba(79, 70, 229, 0.3);
            }
            
            .result {
                display: none;
                background: rgba(16, 185, 129, 0.2);
                border: 1px solid #10b981;
                border-radius: 10px;
                padding: 20px;
                margin: 20px 0;
                color: #ffffff;
            }
            
            .info-box {
                background: rgba(59, 130, 246, 0.2);
                border: 1px solid #3b82f6;
                border-radius: 10px;
                padding: 20px;
                margin: 20px 0;
            }
            
            .warning-box {
                background: rgba(245, 158, 11, 0.2);
                border: 1px solid #f59e0b;
                border-radius: 10px;
                padding: 20px;
                margin: 20px 0;
            }
            
            @media (max-width: 768px) {
                .container {
                    padding: 20px;
                }
                
                h1 {
                    font-size: 2em;
                }
                
                .test-grid {
                    grid-template-columns: 1fr;
                }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🧪 Teste do Sistema de Proxy</h1>
            <p class="subtitle">LinkGate Redirector - Sistema de Redirecionamento via Domínios Ativos</p>
            
            <div class="info-box">
                <h3>ℹ️ Como Funciona o Sistema Simplificado</h3>
                <p><strong>1. Página de Wait:</strong> Usuário vê uma página elegante com countdown de ${CONFIG.WAIT_DELAY_SECONDS} segundos</p>
                <p><strong>2. Redirecionamento Direto:</strong> Após countdown, JavaScript redireciona diretamente</p>
                <p><strong>3. Seleção de Domínio:</strong> Sistema escolhe aleatoriamente um domínio ativo no frontend</p>
                <p><strong>4. Proxy Transparente:</strong> Usuário é enviado para domínio ativo com parâmetro ?url=[base64]</p>
            </div>
            
            <div class="section">
                <h3>🎯 URLs de Teste Pré-Configuradas</h3>
                <div class="test-grid">
                    ${testUrls.map((url, index) => {
                        const encodedUrl = Buffer.from(url).toString('base64');
                        const testUrl = `${baseUrl}/aguarde?a=${encodedUrl}`;
                        return `
                        <div class="test-card">
                            <h4>📍 Teste ${index + 1}</h4>
                            <p><strong>Destino:</strong> ${url}</p>
                            <div class="test-url">${testUrl}</div>
                            <button class="btn btn-copy" onclick="copyToClipboard('${testUrl}')">📋 Copiar URL</button>
                            <a href="${testUrl}" target="_blank" class="btn">🚀 Testar Agora</a>
                        </div>
                        `;
                    }).join('')}
                </div>
            </div>
            
            <div class="custom-test">
                <h3>🔧 Teste Personalizado</h3>
                <p>Insira qualquer URL para testar o sistema de proxy com referer spoofing:</p>
                
                <input type="url" id="customUrl" class="custom-url" placeholder="https://exemplo.com" value="">
                <button class="btn" onclick="generateCustomTest()">🔗 Gerar URL de Teste</button>
                
                <div id="customResult" class="result">
                    <strong>✅ URL de teste gerada com sucesso!</strong><br>
                    <div id="customTestUrl" class="test-url"></div>
                    <button class="btn btn-copy" onclick="copyCustomUrl()">📋 Copiar</button>
                    <a id="customTestLink" href="#" target="_blank" class="btn">🚀 Testar</a>
                </div>
            </div>
            
            <div class="warning-box">
                <h3>⚠️ Configuração Atual</h3>
                <p><strong>Domínios Ativos:</strong> ${CONFIG.ACTIVE_DOMAINS.join(', ')}</p>
                <p><strong>Tempo de Wait:</strong> ${CONFIG.WAIT_DELAY_SECONDS} segundos</p>
                <p><strong>Referers Disponíveis:</strong> ${FAKE_REFERRERS.length} opções (Google, Facebook, YouTube, Instagram, X.com)</p>
                <p><strong>User-Agents:</strong> ${FAKE_USER_AGENTS.length} opções (Chrome, Firefox, Safari, Mobile)</p>
            </div>
            
            <div class="section">
                <h3>📊 Informações Técnicas</h3>
                <div class="test-grid">
                    <div class="test-card">
                        <h4>🔄 Fluxo do Sistema</h4>
                        <p>1. URL de entrada: /aguarde?a=[base64]</p>
                        <p>2. Página de wait com countdown de 3s</p>
                        <p>3. JavaScript seleciona domínio aleatório</p>
                        <p>4. Redirecionamento direto via window.location</p>
                    </div>
                    
                    <div class="test-card">
                        <h4>🛡️ Recursos de Segurança</h4>
                        <p>• Detecção e bloqueio de bots</p>
                        <p>• Validação de URLs Base64</p>
                        <p>• Rate limiting avançado</p>
                        <p>• Headers de segurança</p>
                    </div>
                    
                    <div class="test-card">
                        <h4>📈 Monitoramento</h4>
                        <p>• Logs detalhados de todas as operações</p>
                        <p>• Request IDs únicos para rastreamento</p>
                        <p>• Teste de conectividade de domínios</p>
                        <p>• Fallback automático para domínios</p>
                    </div>
                </div>
            </div>
        </div>
        
        <script>
            let customTestUrl = '';
            
            function copyToClipboard(text) {
                navigator.clipboard.writeText(text).then(() => {
                    alert('✅ URL copiada para a área de transferência!');
                }).catch(err => {
                    console.error('❌ Erro ao copiar:', err);
                    fallbackCopy(text);
                });
            }
            
            function fallbackCopy(text) {
                const textArea = document.createElement('textarea');
                textArea.value = text;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                alert('✅ URL copiada!');
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
                    document.getElementById('customTestLink').href = customTestUrl;
                    document.getElementById('customResult').style.display = 'block';
                } catch (e) {
                    alert('❌ URL inválida! Por favor, insira uma URL completa (ex: https://exemplo.com)');
                }
            }
            
            function copyCustomUrl() {
                copyToClipboard(customTestUrl);
            }
            
            // Auto-focus no campo de URL personalizada
            document.addEventListener('DOMContentLoaded', function() {
                document.getElementById('customUrl').focus();
            });
        </script>
    </body>
    </html>
    `;
    
    res.send(testPageHtml);
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