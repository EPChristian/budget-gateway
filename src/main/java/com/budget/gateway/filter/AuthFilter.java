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
                      @Value("${app.internal.token}") String internalToken) {
        this.webClient = webClientBuilder.baseUrl("http://localhost:8080").build();
        this.internalToken = internalToken;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        if (!exchange.getRequest().getURI().getPath().startsWith("/api/")) {
            return chain.filter(exchange);
        }

        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Basic ")) {
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
                    // Безопасное извлечение userId
                    Object userIdObj = body.get("userId");
                    if (userIdObj == null) {
                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
                    }
                    String userId = userIdObj.toString(); // безопасное преобразование
                    if (userId.isBlank()) {
                        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                        return exchange.getResponse().setComplete();
                    }

                    // Удаляем оригинальный Authorization и добавляем свои заголовки
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
                    // Обработка таймаутов и других ошибок соединения
                    exchange.getResponse().setStatusCode(HttpStatus.GATEWAY_TIMEOUT);
                    return exchange.getResponse().setComplete();
                });
    }

    @Override
    public int getOrder() {
        return -100;
    }
}
