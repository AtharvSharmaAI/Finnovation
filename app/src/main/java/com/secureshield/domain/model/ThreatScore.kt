package com.secureshield.domain.model

/**
 * Represents the final threat assessment outcome for a URL or APK.
 */
enum class ThreatStatus {
    SAFE,
    SUSPICIOUS,
    BLOCKED
}

/**
 * Represents the state of a remote session.
 */
enum class RemoteSessionState {
    INACTIVE,
    ACTIVE_SAFE,
    ACTIVE_HIGH_RISK
}

/**
 * Data class representing the threat score and parameters for a URL.
 */
data class UrlThreatScore(
    val url: String,
    val finalScore: Float, // 0.0 to 1.0 (1.0 being highest risk)
    val status: ThreatStatus,
    val signals: UrlThreatSignals,
    val ruleMatched: String? = null // Indicates if a specific rule bypassed the AI (e.g., known bad domain)
)

/**
 * Breakdown of signals used by the AI Model for URL scoring.
 */
data class UrlThreatSignals(
    val lexicalScore: Float,   // e.g., length, random characters, homoglyphs
    val domainScore: Float,    // e.g., newly registered domain, mismatched TLD
    val redirectScore: Float,  // e.g., excessive redirects, hidden iframes
    val visualScore: Float     // e.g., impersonation of known brands
)

/**
 * Data class representing the evaluation of remote access on the device.
 */
data class RemoteAccessEvaluation(
    val state: RemoteSessionState,
    val activeRemoteApps: List<String>,
    val isScreenCasting: Boolean
)

/**
 * Data class representing a known malicious dropper profile.
 */
data class DropperProfile(
    val profileId: String,
    val description: String,
    val targetPermissions: List<String>,
    val thresholdScore: Float
)

/**
 * Data class representing the threat score evaluated at runtime for an installed app.
 */
data class BehaviorThreatScore(
    val packageName: String,
    val isDropper: Boolean,
    val matchedProfile: DropperProfile?,
    val riskScore: Float,
    val status: ThreatStatus
)

/**
 * Data class representing the outcome of a deep device scan for pre-existing threats.
 */
data class DeepScanThreatScore(
    val compromisedApps: List<String>,
    val fakeBankingApps: List<String>,
    val hardwareIntegrityPassed: Boolean,
    val needsImmediateAction: Boolean
)

/**
 * Data class representing the threat score for an APK.
 */
data class ApkThreatScore(
    val packageName: String,
    val finalScore: Float, // 0.0 to 1.0
    val status: ThreatStatus,
    val isSignatureVerified: Boolean,
    val dangerousPermissionsCount: Int,
    val riskFactors: List<String>
)
