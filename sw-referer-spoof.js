/**
 * LinkGate Service Worker - Referer Spoofing
 * Intercepta requisições e modifica o header Referer
 */

console.log('🚀 LinkGate Service Worker iniciado');

let spoofedReferer = null;
let targetHostname = null;

// Escuta mensagens da página principal
self.addEventListener('message', function(event) {
    console.log('📨 SW recebeu mensagem:', event.data);
    
    if (event.data.action === 'setSpoofConfig') {
        spoofedReferer = event.data.referer;
        targetHostname = event.data.hostname;
        console.log('🎯 Configuração de spoofing definida:', {
            referer: spoofedReferer,
            hostname: targetHostname
        });
        
        // Confirma configuração
        if (event.ports && event.ports[0]) {
            event.ports[0].postMessage({ success: true });
        }
    }
});

// Intercepta todas as requisições de navegação
self.addEventListener('fetch', function(event) {
    const request = event.request;
    const url = new URL(request.url);
    
    // Log de debug para todas as requisições
    console.log('🔍 SW interceptou requisição:', {
        url: request.url,
        method: request.method,
        mode: request.mode,
        destination: request.destination
    });
    
    // Verifica se é uma requisição de navegação para o destino alvo
    if (targetHostname && url.hostname === targetHostname && request.mode === 'navigate') {
        console.log('🎯 Interceptando navegação para destino alvo:', url.hostname);
        
        // Cria uma nova requisição com referer spoofado
        const modifiedHeaders = new Headers(request.headers);
        
        if (spoofedReferer) {
            modifiedHeaders.set('Referer', spoofedReferer);
            modifiedHeaders.set('Referrer', spoofedReferer);
            console.log('🎭 Referer spoofado aplicado:', spoofedReferer);
        }
        
        const modifiedRequest = new Request(request, {
            headers: modifiedHeaders
        });
        
        // Responde com a requisição modificada
        event.respondWith(
            fetch(modifiedRequest)
                .then(response => {
                    console.log('✅ Requisição spoofada enviada com sucesso');
                    return response;
                })
                .catch(error => {
                    console.error('❌ Erro na requisição spoofada:', error);
                    // Fallback para requisição original
                    return fetch(request);
                })
        );
    }
    // Para outras requisições, deixa passar normalmente
    else {
        // Só intercepta se for para o domínio alvo
        if (targetHostname && url.hostname === targetHostname) {
            console.log('🔄 Passando requisição para o destino sem modificação');
        }
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

// Cleanup quando não precisar mais
self.addEventListener('beforeunload', function(event) {
    console.log('🧹 Service Worker sendo limpo');
    spoofedReferer = null;
    targetHostname = null;
});