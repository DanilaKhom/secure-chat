/**
 * Friendly Chat - Cloudflare Worker Reverse Proxy
 * Развертывается в Cloudflare Workers (бесплатный тариф: 100 000 запросов/день).
 * Обеспечивает отказоустойчивый доступ к бэкенду через глобальную CDN сеть Cloudflare.
 */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    // Перенаправляем все запросы на основной сервер
    url.hostname = 'friedlychat.onrender.com';
    url.protocol = 'https:';

    const headers = new Headers(request.headers);
    headers.set('Host', 'friedlychat.onrender.com');

    const newRequest = new Request(url.toString(), {
      method: request.method,
      headers: headers,
      body: request.body,
      redirect: 'follow'
    });

    return fetch(newRequest);
  }
};
