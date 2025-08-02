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
    // Domínios ativos para redirecionamento
    ACTIVE_DOMAINS: [
        'https://evoapi-wp.ttvjwi.easypanel.host'    ],
    
    // Se deve fazer redirecionamento após proxy (true/false)
    REDIRECT_AFTER_PROXY: false,
    
    // Delay antes do redirecionamento (em ms)
    REDIRECT_DELAY: 3000
};

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

// Função para fazer proxy transparente com referer spoofing
async function fetchProxyWithSpoof(url, userAgent = null) {
    const referer = getRandomReferrer();
    const finalUserAgent = userAgent || getRandomUserAgent();
    
    console.log(`🎯 Proxy request to: ${url}`);
    console.log(`🎲 Using spoofed referer: ${referer}`);
    console.log(`🎭 Using user-agent: ${finalUserAgent.substring(0, 50)}...`);
    
    try {
        // Faz requisição completa com cURL para obter o conteúdo
        const curlCommand = `curl -s -L --max-redirs 5 --referer "${referer}" --user-agent "${finalUserAgent}" "${url}"`;
        const { stdout, stderr } = await execAsync(curlCommand);
        
        if (stderr) {
            console.log(`⚠️ cURL stderr: ${stderr}`);
        }
        
        console.log(`✅ Proxy request successful with spoofed referer: ${referer}`);
        return { 
            success: true, 
            content: stdout, 
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
    // Página de carregamento primeiro
    const loadingHtml = `
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <meta name="robots" content="noindex, nofollow, noarchive, nosnippet, noimageindex">
        <meta name="googlebot" content="noindex, nofollow, noarchive, nosnippet, noimageindex">
        <meta name="referrer" content="no-referrer">
        <title>Redirecionando...</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                background: #0f0f0f;
                color: #ffffff;
                min-height: 100vh;
                display: flex;
                flex-direction: column;
                justify-content: center;
                align-items: center;
                padding: 20px;
                margin: 0;
            }
            
            .loading-content {
                text-align: center;
                max-width: 400px;
                width: 100%;
            }
            
            .spinner {
                width: 80px;
                height: 80px;
                border: 4px solid rgba(79, 70, 229, 0.2);
                border-top: 4px solid #4f46e5;
                border-radius: 50%;
                animation: spin 1.2s linear infinite;
                margin: 0 auto 40px;
                filter: drop-shadow(0 0 20px rgba(79, 70, 229, 0.3));
            }
            
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
            
            h1 {
                font-size: 2.5rem;
                font-weight: 300;
                color: #ffffff;
                margin-bottom: 20px;
                letter-spacing: -0.02em;
                text-shadow: 0 2px 4px rgba(0,0,0,0.5);
            }
            
            .subtitle {
                font-size: 1.1rem;
                color: #a0a0a0;
                margin-bottom: 40px;
                line-height: 1.6;
                font-weight: 400;
            }
            
            .progress-wrapper {
                width: 100%;
                margin-bottom: 30px;
            }
            
            .progress-bar {
                width: 100%;
                height: 3px;
                background-color: rgba(79, 70, 229, 0.2);
                border-radius: 50px;
                overflow: hidden;
                margin-bottom: 20px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.2);
            }
            
            .progress {
                height: 100%;
                background: linear-gradient(90deg, #4f46e5, #7c3aed, #4f46e5);
                background-size: 200% 100%;
                width: 0%;
                border-radius: 50px;
                animation: progress 3s ease-out forwards, shimmer 2s linear infinite;
                box-shadow: 0 0 10px rgba(79, 70, 229, 0.5);
            }
            
            @keyframes progress {
                0% { width: 0%; }
                100% { width: 100%; }
            }
            
            @keyframes shimmer {
                0% { background-position: -200% 0; }
                100% { background-position: 200% 0; }
            }
            
            .status-text {
                font-size: 1rem;
                color: #8b7ee8;
                font-weight: 500;
                letter-spacing: 0.5px;
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
                h1 {
                    font-size: 2rem;
                }
                
                .subtitle {
                    font-size: 1rem;
                }
                
                .spinner {
                    width: 60px;
                    height: 60px;
                    margin-bottom: 30px;
                }
            }
            
            @media (max-width: 320px) {
                h1 {
                    font-size: 1.8rem;
                }
                
                .spinner {
                    width: 50px;
                    height: 50px;
                }
            }
            
            /* Modo landscape mobile */
            @media (max-height: 500px) and (orientation: landscape) {
                h1 {
                    font-size: 1.8rem;
                    margin-bottom: 15px;
                }
                
                .subtitle {
                    font-size: 0.95rem;
                    margin-bottom: 25px;
                }
                
                .spinner {
                    width: 50px;
                    height: 50px;
                    margin-bottom: 25px;
                }
            }
        </style>
    </head>
    <body>
        <div class="loading-content">
            <div class="spinner"></div>
            <h1>Redirecionando</h1>
            <p class="subtitle">Preparando acesso ao destino</p>
            
            <div class="progress-wrapper">
                <div class="progress-bar">
                    <div class="progress"></div>
                </div>
                <div class="status-text">
                    Processando<span class="dots"></span>
                </div>
            </div>
        </div>
        
        <script>
            // Detecta e bloqueia bots
            const userAgent = navigator.userAgent.toLowerCase();
            const botPatterns = [
                'googlebot', 'bingbot', 'slurp', 'duckduckbot', 'baiduspider',
                'yandexbot', 'facebookexternalhit', 'twitterbot', 'rogerbot',
                'linkedinbot', 'embedly', 'quora link preview', 'showyoubot',
                'outbrain', 'pinterest', 'developers.google.com/+/web/snippet',
                'slackbot', 'vkshare', 'w3c_validator', 'redditbot', 'applebot',
                'whatsapp', 'flipboard', 'tumblr', 'bitlybot', 'skypeuripreview',
                'nuzzel', 'discordbot', 'telegrambot', 'google-structured-data-testing-tool'
            ];
            
            const isBot = botPatterns.some(pattern => userAgent.includes(pattern));
            
            if (isBot) {
                document.body.innerHTML = '<div style="text-align:center;padding:50px;color:#666;">Acesso restrito</div>';
                console.log('Bot detectado e bloqueado');
            } else {
                // Após 3 segundos, fazer requisição AJAX para processar proxy em background
                setTimeout(() => {
                    const currentUrl = new URL(window.location.href);
                    const urlParam = currentUrl.searchParams.get('a');
                    
                    // Fazer requisição AJAX para processar proxy
                    fetch('/proxy-execute', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({
                            encodedUrl: urlParam
                        })
                    })
                    .then(response => response.text())
                    .then(html => {
                        // Substituir o conteúdo da página pelo resultado do proxy
                        document.open();
                        document.write(html);
                        document.close();
                    })
                    .catch(error => {
                        console.error('Erro no proxy:', error);
                        document.body.innerHTML = '<div style="text-align:center;padding:50px;color:#f44336;">Erro ao processar requisição</div>';
                    });
                }, 3000);
                
                // Contador visual
                let seconds = 3;
                const statusText = document.querySelector('.status-text');
                
                const countdown = setInterval(() => {
                    seconds--;
                    if (seconds > 0) {
                        statusText.innerHTML = \`Processando em \${seconds}s<span class="dots"></span>\`;
                    } else {
                        statusText.innerHTML = 'Executando proxy<span class="dots"></span>';
                        clearInterval(countdown);
                    }
                }, 1000);
            }
        </script>
    </body>
    </html>
    `;

    // Sempre mostra a página de carregamento primeiro
    logger.info(`📄 Showing loading page for: ${req.originalUrl}`);
    console.log(`📄 Loading page displayed, will process proxy after 3 seconds`);
    return res.send(loadingHtml);
});

// Endpoint para processar proxy via AJAX
app.post('/proxy-execute', async (req, res) => {
    const { encodedUrl } = req.body;

    if (!encodedUrl) {
        logger.warn('Access to /proxy-execute without encodedUrl parameter.');
        return res.status(400).send('encodedUrl parameter not found.');
    }

    let targetUrl;
    try {
        targetUrl = Buffer.from(encodedUrl, 'base64').toString('utf8');
        if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
            throw new Error('Invalid URL format.');
        }
    } catch (e) {
        logger.warn(`Invalid Base64 or URL in encodedUrl parameter: ${encodedUrl}`);
        return res.status(400).send('Invalid encodedUrl parameter. Must be a valid Base64 encoded URL.');
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
                        background: white;
                        padding: 30px;
                        border-radius: 15px;
                        box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                        max-width: 600px;
                        width: 100%;
                    }
                    h1 {
                        color: #4CAF50;
                        text-align: center;
                        margin-bottom: 30px;
                        font-size: 2.2em;
                    }
                    .detail {
                        background: #f8f9fa;
                        padding: 15px;
                        margin: 15px 0;
                        border-radius: 8px;
                        border-left: 4px solid #4CAF50;
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

        // Se for uma URL externa, usa proxy transparente com referer spoofing
        logger.info(`Starting proxy to: ${targetUrl}`);
        
        try {
            // Seleciona domínio ativo e constrói URL do proxy
            const activeDomain = getRandomActiveDomain();
            const encodedUrlForProxy = Buffer.from(targetUrl).toString('base64');
            const proxyUrl = `${activeDomain}/redirect.php?url=${encodedUrlForProxy}`;
            
            // Faz requisição proxy através do domínio ativo com referer spoofado
            const proxyResult = await fetchProxyWithSpoof(proxyUrl, req.headers['user-agent']);
            
            logger.info(`✅ Proxy request successful through active domain with referer: ${proxyResult.referer}`);
            console.log(`🎯 Proxied to: ${proxyUrl} with spoofed referer: ${proxyResult.referer}`);
            console.log(`🎭 Used user-agent: ${proxyResult.userAgent.substring(0, 50)}...`);
            
            // Detectar content-type baseado no conteúdo
            let contentType = 'text/html; charset=utf-8';
            const trimmedContent = proxyResult.content.trim();
            
            // Detectar JSON
            if (trimmedContent.startsWith('{') && trimmedContent.endsWith('}')) {
                contentType = 'application/json';
            } 
            // Detectar XML
            else if (trimmedContent.startsWith('<?xml') || trimmedContent.startsWith('<xml')) {
                contentType = 'text/xml; charset=utf-8';
            }
            // Default para HTML - isso vai renderizar o HTML corretamente
            else {
                contentType = 'text/html; charset=utf-8';
            }
            
            // Headers informativos sobre o proxy
            res.setHeader('Content-Type', contentType);
            res.setHeader('X-Spoofed-Referer', proxyResult.referer);
            res.setHeader('X-Proxy-Through', proxyUrl);
            res.setHeader('X-Original-Target', targetUrl);
            res.setHeader('X-Proxy-By', 'LinkGate-Redirector');
            
            // Retornar o conteúdo obtido através do proxy
            res.send(proxyResult.content);
            return;
            
        } catch (error) {
            logger.error(`❌ Proxy request failed: ${error.message}`);
            console.log(`💥 Proxy error: ${error.message}`);
            
            // Página de erro
            const errorHtml = `
            <!DOCTYPE html>
            <html lang="pt-BR">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Erro no Proxy</title>
                <style>
                    body {
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                        background: #0f0f0f;
                        color: #ffffff;
                        min-height: 100vh;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        margin: 0;
                        text-align: center;
                    }
                    .error-container {
                        max-width: 500px;
                        padding: 40px;
                        background: rgba(255, 255, 255, 0.05);
                        border-radius: 15px;
                        border: 1px solid rgba(244, 67, 54, 0.3);
                    }
                    h1 {
                        color: #f44336;
                        margin-bottom: 20px;
                    }
                    p {
                        color: #a0a0a0;
                        margin-bottom: 20px;
                    }
                    .error-detail {
                        background: rgba(244, 67, 54, 0.1);
                        padding: 15px;
                        border-radius: 8px;
                        margin: 20px 0;
                        border-left: 4px solid #f44336;
                    }
                    code {
                        background: rgba(0, 0, 0, 0.3);
                        padding: 2px 6px;
                        border-radius: 3px;
                        font-family: monospace;
                    }
                </style>
            </head>
            <body>
                <div class="error-container">
                    <h1>❌ Erro no Proxy</h1>
                    <p>Ocorreu um erro ao processar a requisição através do proxy.</p>
                    <div class="error-detail">
                        <strong>Erro:</strong><br>
                        <code>${error.message}</code>
                    </div>
                    <div class="error-detail">
                        <strong>URL Alvo:</strong><br>
                        <code>${targetUrl}</code>
                    </div>
                </div>
            </body>
            </html>
            `;
            
            res.status(500).send(errorHtml);
            return;
        }
        
    } catch (error) {
        logger.error(`❌ Target URL processing error: ${error.message}`);
        res.status(400).send(`Erro ao processar URL: ${error.message}`);
        return;
    }
});
