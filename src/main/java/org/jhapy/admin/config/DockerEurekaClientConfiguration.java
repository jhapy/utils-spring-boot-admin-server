/*
 * Copyright 2020-2020 the original author or authors from the JHapy project.
 *
 * This file is part of the JHapy project, see https://www.jhapy.org/ for more information.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jhapy.admin.config;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import org.apache.commons.net.util.SubnetUtils;
import org.jhapy.commons.utils.HasLogger;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.cloud.commons.util.IdUtils;
import org.springframework.cloud.commons.util.InetUtils;
import org.springframework.cloud.netflix.eureka.EurekaClientConfigBean;
import org.springframework.cloud.netflix.eureka.EurekaInstanceConfigBean;
import org.springframework.cloud.netflix.eureka.metadata.ManagementMetadata;
import org.springframework.cloud.netflix.eureka.metadata.ManagementMetadataProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.util.StringUtils;


@Configuration
@ConditionalOnProperty(value = "spring.cloud.kubernetes.enabled", havingValue = "false", matchIfMissing = true)
public class DockerEurekaClientConfiguration implements
    HasLogger {

  private final ConfigurableEnvironment env;

  public DockerEurekaClientConfiguration(ConfigurableEnvironment env) {
    String loggerPrefix = getLoggerPrefix("DockerEurekaClientConfiguration");
    logger().info(loggerPrefix + "Startup");
    this.env = env;
  }

  @Bean
  @Primary
  public EurekaClientConfigBean eurekaClientConfigBean(ConfigurableEnvironment env) {
    EurekaClientConfigBean client = new EurekaClientConfigBean();
    if ("bootstrap".equals(this.env.getProperty("spring.config.name"))) {
      client.setRegisterWithEureka(false);
    }

    return client;
  }

  @Bean
  @Primary
  public EurekaInstanceConfigBean eurekaInstanceConfigBean(InetUtils inetUtils,
      ManagementMetadataProvider managementMetadataProvider) {
    String loggerPrefix = getLoggerPrefix("eurekaInstanceConfigBean");

    String hostname = env.getProperty("eureka.instance.hostname");
    boolean preferIpAddress = Boolean
        .parseBoolean(env.getProperty("eureka.instance.prefer-ip-address"));
    String ipAddress = env.getProperty("eureka.instance.ip-address");
    boolean isSecurePortEnabled = Boolean
        .parseBoolean(env.getProperty("eureka.instance.secure-port-enabled"));
    String serverContextPath = this.env.getProperty("server.servlet.context-path", "/");
    int serverPort = Integer
        .parseInt(this.env.getProperty("server.port", this.env.getProperty("port", "8080")));
    Integer managementPort = this.env
        .getProperty("management.server.port", Integer.class, serverPort);
    Boolean isManagementSecuredPortEnabled = this.env
        .getProperty("management.server.ssl.enabled", Boolean.class, false);
    String managementContextPath = this.env.getProperty("management.servlet.context-path",
        this.env.getProperty("management.endpoints.web.base-path", "/management"));
    Integer jmxPort = this.env.getProperty("com.sun.management.jmxremote.port", Integer.class);
    EurekaInstanceConfigBean instance = new EurekaInstanceConfigBean(inetUtils);
    instance.setNonSecurePort(serverPort);
    instance.setInstanceId(IdUtils.getDefaultInstanceId(this.env));
    instance.setPreferIpAddress(preferIpAddress);
    instance.setSecurePortEnabled(isSecurePortEnabled);
    if (StringUtils.hasText(ipAddress)) {
      instance.setIpAddress(ipAddress);
    }

    if (isSecurePortEnabled) {
      instance.setSecurePort(serverPort);
    }

    if (StringUtils.hasText(hostname)) {
      instance.setHostname(hostname);
    }

    String statusPageUrlPath = env.getProperty("eureka.instance.status-page-url-path");
    String healthCheckUrlPath = env.getProperty("eureka.instance.health-check-url-path");
    if (StringUtils.hasText(statusPageUrlPath)) {
      instance.setStatusPageUrlPath(statusPageUrlPath);
    }

    if (StringUtils.hasText(healthCheckUrlPath)) {
      instance.setHealthCheckUrlPath(healthCheckUrlPath);
    }

    ManagementMetadata metadata = managementMetadataProvider
        .get(instance, serverPort, serverContextPath, managementContextPath, managementPort);
    if (metadata != null) {
      instance.setStatusPageUrl(metadata.getStatusPageUrl());
      instance.setHealthCheckUrl(metadata.getHealthCheckUrl());
      if (instance.isSecurePortEnabled()) {
        instance.setSecureHealthCheckUrl(metadata.getSecureHealthCheckUrl());
      }

      Map<String, String> metadataMap = instance.getMetadataMap();
      metadataMap.computeIfAbsent("management.port", (k) -> {
        return String.valueOf(metadata.getManagementPort());
      });
    } else if (StringUtils.hasText(managementContextPath)) {
      instance.setHealthCheckUrlPath(managementContextPath + instance.getHealthCheckUrlPath());
      instance.setStatusPageUrlPath(managementContextPath + instance.getStatusPageUrlPath());
    }

    this.setupJmxPort(instance, jmxPort);

    EurekaInstanceConfigBean result = null;
    SubnetUtils subnet = null;
    if (env.getProperty("eureka.instance.network") != null) {
      String specifiedNetwork = env.getProperty("eureka.instance.network");
      logger().info(loggerPrefix + "Network is specified : " + specifiedNetwork);
      subnet = new SubnetUtils(specifiedNetwork);
    }

    int nbLoop = 1;
    while (result == null & nbLoop <= 10) {
      logger().info(loggerPrefix + "Loop " + nbLoop++);
      try {
        List<String> servers = eurekaClientConfigBean(env).getEurekaServerServiceUrls(null);
        Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();

        external_loop:
        for (NetworkInterface networkInterface : Collections.list(networkInterfaces)) {
          for (InterfaceAddress interfaceAddress : networkInterface.getInterfaceAddresses()) {
            if (interfaceAddress.getAddress() instanceof Inet4Address) {
              logger().info(loggerPrefix +
                      "Interface {}: {}/{}",
                  networkInterface.getName(),
                  interfaceAddress.getAddress(),
                  interfaceAddress.getNetworkPrefixLength()
              );

              if (subnet != null) {
                if (subnet.getInfo().isInRange(interfaceAddress.getAddress().getHostAddress())) {
                  logger().info(loggerPrefix + "Interface match with specified network");
                  result = createEurekaInstanceConfigBean(inetUtils, instance,
                      isManagementSecuredPortEnabled, managementContextPath, interfaceAddress);
                  break external_loop;
                }
              } else {
                SubnetUtils addressSubnet = new SubnetUtils(
                    interfaceAddress.getAddress().getHostAddress() +
                        "/" + interfaceAddress.getNetworkPrefixLength()
                );
                logger().info(loggerPrefix + servers.size() + " servers to check");
                for (String server : servers) {
                  URL serverUrl = new URL(server);
                  try {
                    InetAddress eurekaServerAddress = InetAddress.getByName(serverUrl.getHost());
                    boolean matches = addressSubnet.getInfo()
                        .isInRange(eurekaServerAddress.getHostAddress());
                    logger().info(loggerPrefix + "Testing server {} ({}): {}", server,
                        eurekaServerAddress.getHostAddress(), matches);
                    if (matches) {
                      logger().info(loggerPrefix +
                              "Found Interface {}: {} ({})",
                          networkInterface.getName(),
                          interfaceAddress.getAddress().getHostName(),
                          interfaceAddress.getAddress().getHostAddress()
                      );
                      result = createEurekaInstanceConfigBean(inetUtils, instance,
                          isManagementSecuredPortEnabled, managementContextPath, interfaceAddress);
                      break external_loop;
                    }
                  } catch (UnknownHostException e) {
                    logger().warn(loggerPrefix + "Host not found on interface");
                  }
                }
              }
            } else {
              logger().info(loggerPrefix +
                      "Skipping IPv6 from Interface {}: {}/{}",
                  networkInterface.getName(),
                  interfaceAddress.getAddress(),
                  interfaceAddress.getNetworkPrefixLength()
              );
            }
          }
        }
      } catch (Exception e) {
        logger().error(loggerPrefix + "Error while detecting eureka client address", e);
      }
      try {
        Thread.sleep(1000);
      } catch (InterruptedException e) {
      }
    }
    if (result == null) {
      logger().error(loggerPrefix + "Unable to getEurekaInstance, exiting");
      System.exit(-1);
    }
    return result;
  }

  private void setupJmxPort(EurekaInstanceConfigBean instance, Integer jmxPort) {
    Map<String, String> metadataMap = instance.getMetadataMap();
    if (metadataMap.get("jmx.port") == null && jmxPort != null) {
      metadataMap.put("jmx.port", String.valueOf(jmxPort));
    }
  }

  private EurekaInstanceConfigBean createEurekaInstanceConfigBean(InetUtils inetUtils,
      EurekaInstanceConfigBean defaultResult, Boolean isManagementSecuredPortEnabled,
      String managementContextPath, InterfaceAddress interfaceAddress) {
    String loggerPrefix = getLoggerPrefix("createEurekaInstanceConfigBean");

    EurekaInstanceConfigBean result;
    result = new EurekaInstanceConfigBean(inetUtils);
    result.setPreferIpAddress(defaultResult.isPreferIpAddress());
    result.setHostname(defaultResult.getHostname());
    result.setIpAddress(interfaceAddress.getAddress().getHostAddress());
    result.setSecurePortEnabled(defaultResult.isSecurePortEnabled());
    result.setSecurePort(defaultResult.getSecurePort());
    result.setNonSecurePortEnabled(defaultResult.isNonSecurePortEnabled());
    result.setNonSecurePort(defaultResult.getNonSecurePort());

    String managementUrl;
    if (isManagementSecuredPortEnabled) {
      managementUrl = "https://";
    } else {
      managementUrl = "http://";
    }
    if (defaultResult.isPreferIpAddress()) {
      managementUrl += result.getIpAddress();
    } else {
      managementUrl += result.getHostname();
    }

    managementUrl += ":" + defaultResult.getMetadataMap().get("management.port");

    managementUrl += managementContextPath;
    logger().info(loggerPrefix + "Management url = " + managementUrl);

    defaultResult.getMetadataMap().put("management.url", managementUrl);
    result.setMetadataMap(defaultResult.getMetadataMap());
    result.setInstanceId(result.getInstanceId());
    result.setHealthCheckUrlPath(defaultResult.getHealthCheckUrlPath());
    result.setHealthCheckUrl(defaultResult.getHealthCheckUrl());
    result.setStatusPageUrlPath(defaultResult.getStatusPageUrlPath());
    result.setStatusPageUrl(defaultResult.getStatusPageUrl());
    return result;
  }
}
