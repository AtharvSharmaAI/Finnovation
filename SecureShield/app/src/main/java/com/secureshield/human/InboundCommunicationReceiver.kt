package com.secureshield.human

import com.secureshield.domain.model.CommunicationType
import kotlinx.coroutines.flow.Flow

/**
 * Data object representing an incoming communication event.
 */
data class InboundMessage(
    val type: CommunicationType,
    val senderId: String,
    val content: String? = null // Nullable for calls
)

/**
 * Interface to abstract receiving SMS/Calls and pushing them to the analysis pipeline.
 */
interface InboundCommunicationReceiver {

    /**
     * Emits a stream of incoming messages or call events intercepted by BroadcastReceivers
     * or AccessibilityService.
     */
    fun observeInboundCommunications(): Flow<InboundMessage>

    /**
     * Displays a system-level real-time alert overlay warning the user of a detected threat.
     * Requires SYSTEM_ALERT_WINDOW permission.
     */
    fun showRealTimeAlert(senderId: String, warningMessage: String)

    /**
     * Executes the block action if supported (e.g., TelecomManager.endCall() or dropping SMS).
     */
    fun blockCommunication(senderId: String)
}
