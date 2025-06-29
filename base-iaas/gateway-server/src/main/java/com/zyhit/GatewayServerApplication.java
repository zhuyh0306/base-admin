package com.zyhit;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import com.zyhit.filter.TokenCheckFilter;

@SpringBootApplication
@EnableDiscoveryClient
public class GatewayServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(GatewayServerApplication.class, args);
    }

    @Bean
    public CommandLineRunner printGlobalFilters(ApplicationContext ctx) {
        return args -> {
            System.out.println("=== 注册的全局过滤器 ===");
            ctx.getBeansOfType(GlobalFilter.class).forEach((name, bean) -> {
                System.out.println(name + " -> " + bean.getClass().getName());
            });
            System.out.println("=== 全局过滤器列表结束 ===");
            
            System.out.println("=== 检查TokenCheckFilter Bean ===");
            try {
                TokenCheckFilter tokenCheckFilter = ctx.getBean(TokenCheckFilter.class);
                System.out.println("✅ TokenCheckFilter Bean 存在: " + tokenCheckFilter.getClass().getName());
            } catch (Exception e) {
                System.out.println("❌ TokenCheckFilter Bean 不存在: " + e.getMessage());
            }
            
            System.out.println("=== 检查所有@Component注解的Bean ===");
            ctx.getBeansWithAnnotation(org.springframework.stereotype.Component.class).forEach((name, bean) -> {
                System.out.println(name + " -> " + bean.getClass().getName());
            });
        };
    }
}

