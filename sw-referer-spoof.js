/**
 * LinkGate Service Worker - Referer Spoofing
 * Intercepta requisições e modifica o header Referer
 */

console.log('🚀 LinkGate Service Worker iniciado');

let spoofedReferer = null;
let targetUrl = null;
let targetHostname = null;

// Escuta mensagens da página principal
self.addEventListener('message', function(event) {
    console.log('📨 SW recebeu mensagem:', event.data);
    
    if (event.data.action === 'setSpoofConfig') {
        spoofedReferer = event.data.referer;
        targetUrl = event.data.targetUrl;
        targetHostname = event.data.hostname;
        console.log('🎯 Configuração de spoofing definida:', {
            referer: spoofedReferer,
            targetUrl: targetUrl,
            hostname: targetHostname
        });
        
        // Confirma configuração
        if (event.ports && event.ports[0]) {
            event.ports[0].postMessage({ success: true });
        }
    } else if (event.data.action === 'fetchWithSpoof') {
        // Faz requisição com referer spoofado e retorna o conteúdo
        console.log('🎯 Fazendo requisição spoofada para:', event.data.url);
        
        const channel = new MessageChannel();
        
        fetch(event.data.url, {
            headers: {
                'Referer': spoofedReferer,
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            },
            mode: 'cors',
            credentials: 'omit'
        })
        .then(response => {
            console.log('✅ Requisição spoofada bem-sucedida:', response.status);
            return response.text();
        })
        .then(html => {
            console.log('📄 Conteúdo recebido, tamanho:', html.length);
            if (event.ports && event.ports[0]) {
                event.ports[0].postMessage({ 
                    success: true, 
                    html: html,
                    spoofedReferer: spoofedReferer
                });
            }
        })
        .catch(error => {
            console.error('❌ Erro na requisição spoofada:', error);
            if (event.ports && event.ports[0]) {
                event.ports[0].postMessage({ 
                    success: false, 
                    error: error.message 
                });
            }
        });
    }
});

// Intercepta TODAS as requisições para qualquer domínio
self.addEventListener('fetch', function(event) {
    const request = event.request;
    const url = new URL(request.url);
    
    // Só loga requisições importantes para não poluir o console
    if (request.mode === 'navigate' || (targetHostname && url.hostname === targetHostname)) {
        console.log('🔍 SW interceptou:', {
            url: request.url,
            method: request.method,
            mode: request.mode,
            destination: request.destination,
            referer: request.headers.get('referer')
        });
    }
    
    // Intercepta requisições para o destino alvo
    if (targetHostname && url.hostname === targetHostname) {
        console.log('🎯 Interceptando requisição para destino alvo:', url.hostname);
        
        // Clona headers e adiciona referer spoofado
        const newHeaders = new Headers();
        
        // Copia headers existentes
        for (const [key, value] of request.headers.entries()) {
            if (key.toLowerCase() !== 'referer' && key.toLowerCase() !== 'referrer') {
                newHeaders.set(key, value);
            }
        }
        
        // Adiciona referer spoofado
        if (spoofedReferer) {
            newHeaders.set('Referer', spoofedReferer);
            console.log('🎭 Referer spoofado aplicado:', spoofedReferer);
        }
        
        // Cria nova requisição
        const modifiedRequest = new Request(request.url, {
            method: request.method,
            headers: newHeaders,
            body: request.body,
            mode: request.mode === 'navigate' ? 'cors' : request.mode,
            credentials: 'omit',
            cache: request.cache,
            redirect: request.redirect
        });
        
        // Responde com a requisição modificada
        event.respondWith(
            fetch(modifiedRequest)
                .then(response => {
                    console.log('✅ Requisição spoofada enviada:', response.status);
                    return response;
                })
                .catch(error => {
                    console.error('❌ Erro na requisição spoofada:', error);
                    // Fallback para requisição original sem spoofing
                    return fetch(request);
                })
        );
    }
});

// Evento de instalação
self.addEventListener('install', function(event) {
    console.log('⚙️ Service Worker instalado');
    // Pula a fase de espera e ativa imediatamente
    self.skipWaiting();
});

// Evento de ativação
self.addEventListener('activate', function(event) {
    console.log('✅ Service Worker ativado');
    // Toma controle de todas as páginas imediatamente
    event.waitUntil(self.clients.claim());
});

// Cleanup
self.addEventListener('beforeunload', function(event) {
    console.log('🧹 Service Worker cleanup');
    spoofedReferer = null;
    targetUrl = null;
    targetHostname = null;
});