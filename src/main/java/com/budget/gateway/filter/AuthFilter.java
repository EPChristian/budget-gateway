package com.budget.gateway.filter;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Map;

@Component
public class AuthFilter implements GlobalFilter, Ordered {

    private final WebClient webClient;
    private final String internalToken;

    public AuthFilter(WebClient.Builder webClientBuilder,
                      @Value("${app.auth-service.url}") String authServiceUrl,
                      @Value("${app.internal.token}") String internalToken) {
        this.webClient = webClientBuilder.baseUrl(authServiceUrl).build();
        this.internalToken = internalToken;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();
        String method = exchange.getRequest().getMethod().name(); // Получаем метод (POST, GET и т.д.)

        // Проверяем, что путь начинается с /api или /api/
        if (!path.startsWith("/api") || path.equals("/api")) {
            // Защита от пути "/api" без слеша – пропускаем (но такого маршрута нет)
            return chain.filter(exchange);
        }

        // Пропускаем БЕЗ Basic Auth ТОЛЬКО метод POST для регистрации
        if ("/api/users".equals(path) && "POST".equalsIgnoreCase(method)) {
            ServerWebExchange mutatedExchange = exchange.mutate()
                    .request(builder -> builder.headers(headers -> {
                        headers.set("X-Internal-Token", internalToken);
                    }))
                    .build();
            return chain.filter(mutatedExchange);
        }

        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        // case-insensitive проверка на "Basic "
        if (authHeader == null || !authHeader.regionMatches(true, 0, "Basic ", 0, 6)) {
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        return webClient.post()
                .uri("/api/auth/verify")
                .header(HttpHeaders.AUTHORIZATION, authHeader)
                .retrieve()
                .bodyToMono(Map.class)
                .timeout(Duration.ofSeconds(5))
                .flatMap(body -> {
                    if (body == null || body.isEmpty()) {
                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
                    }
                    Object userIdObj = body.get("userId");
                    if (userIdObj == null) {
                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
                    }
                    String userId = userIdObj.toString();
                    if (userId.isBlank()) {
                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
                    }

                    // Удаляем Authorization, добавляем свои заголовки
                    ServerWebExchange mutatedExchange = exchange.mutate()
                            .request(builder -> builder
                                    .headers(headers -> {
                                        headers.remove(HttpHeaders.AUTHORIZATION);
                                        headers.set("X-User-Id", userId);
                                        headers.set("X-Internal-Token", internalToken);
                                    }))
                            .build();
                    return chain.filter(mutatedExchange);
                })
                .onErrorResume(WebClientResponseException.class, ex -> {
                    int statusCode = ex.getStatusCode().value();
                    if (statusCode == HttpStatus.UNAUTHORIZED.value()) {
                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    } else if (statusCode >= 500 && statusCode < 600) {
                        exchange.getResponse().setStatusCode(HttpStatus.BAD_GATEWAY);
                    } else {
                        exchange.getResponse().setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
                    }
                    return exchange.getResponse().setComplete();
                })
                .onErrorResume(e -> {
                    // Для таймаутов и ошибок соединения
                    exchange.getResponse().setStatusCode(HttpStatus.GATEWAY_TIMEOUT);
                    return exchange.getResponse().setComplete();
                });
    }

    @Override
    public int getOrder() {
        return -100;
    }
}