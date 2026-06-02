package com.secureshield.gateway

import kotlinx.coroutines.flow.Flow

/**
 * Interface representing the primary interception point for web traffic.
 * Can be implemented by a VpnService or AccessibilityService.
 */
interface GatewayInterceptor {
    
    /**
     * Starts the interception service to monitor and filter web traffic.
     */
    fun startIntercepting()

    /**
     * Stops the interception service.
     */
    fun stopIntercepting()

    /**
     * Emits URLs intercepted by the Gateway.
     * @return Flow of intercepted URL strings.
     */
    fun observeInterceptedUrls(): Flow<String>

    /**
     * Executes the block action (e.g., redirecting to a safe warning page or blocking the network packet).
     * @param url The malicious URL to block.
     */
    fun blockUrl(url: String)
    
    /**
     * Executes the allow action (e.g., passing the network packet through).
     * @param url The safe URL to allow.
     */
    fun allowUrl(url: String)
}
