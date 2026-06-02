package com.secureshield.human

import com.secureshield.domain.model.CommunicationThreatScore
import com.secureshield.domain.model.CommunicationType
import com.secureshield.domain.model.NlpThreatSignals
import com.secureshield.domain.model.ThreatStatus

/**
 * Evaluates message content for social engineering patterns using NLP heuristics.
 */
interface NlpMessageAnalyzer {
    
    /**
     * Analyzes the content of an SMS or WhatsApp message to determine if it's a scam.
     */
    suspend fun analyzeMessage(
        senderId: String, 
        content: String, 
        isKnownFraud: Boolean
    ): CommunicationThreatScore
}

/**
 * Stubbed implementation that evaluates message content using keyword heuristics.
 */
class NlpMessageAnalyzerImpl : NlpMessageAnalyzer {

    override suspend fun analyzeMessage(
        senderId: String,
        content: String,
        isKnownFraud: Boolean
    ): CommunicationThreatScore {
        
        val lowercaseContent = content.lowercase()
        
        // 1. Detect Urgency
        val urgencyKeywords = listOf("urgent", "immediate", "suspended", "blocked", "act now")
        val urgencyScore = if (urgencyKeywords.any { lowercaseContent.contains(it) }) 0.8f else 0.1f
        
        // 2. Detect Impersonation (e.g., claiming to be a bank without matching the verified sender ID)
        val bankKeywords = listOf("bank", "sbi", "hdfc", "icici", "account")
        val impersonationScore = if (bankKeywords.any { lowercaseContent.contains(it) }) 0.7f else 0.1f
        
        // 3. Detect OTP Requests
        val otpKeywords = listOf("otp", "code", "pin", "password", "verification")
        val otpRequestDetected = otpKeywords.any { lowercaseContent.contains(it) }

        val nlpSignals = NlpThreatSignals(
            urgencyScore = urgencyScore,
            impersonationScore = impersonationScore,
            otpRequestDetected = otpRequestDetected
        )

        // 4. Calculate Final Threat Score
        var finalScore = 0.0f
        if (isKnownFraud) finalScore += 0.8f
        
        if (otpRequestDetected && urgencyScore > 0.5f) finalScore += 0.6f
        else if (otpRequestDetected || urgencyScore > 0.5f) finalScore += 0.3f
        
        finalScore = finalScore.coerceAtMost(1.0f)

        val status = when {
            finalScore >= 0.75f -> ThreatStatus.BLOCKED
            finalScore >= 0.4f -> ThreatStatus.SUSPICIOUS
            else -> ThreatStatus.SAFE
        }

        return CommunicationThreatScore(
            type = CommunicationType.SMS,
            senderId = senderId,
            finalScore = finalScore,
            status = status,
            isKnownFraudNumber = isKnownFraud,
            nlpSignals = nlpSignals
        )
    }
}
