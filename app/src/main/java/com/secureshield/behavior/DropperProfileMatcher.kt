package com.secureshield.behavior

import com.secureshield.domain.model.DropperProfile

/**
 * Interface for matching an app's requested/granted permissions against known malicious profiles.
 */
interface DropperProfileMatcher {

    /**
     * Evaluates a list of permissions to see if they match any known dropper signatures.
     * 
     * @param permissions The list of permissions requested by the app.
     * @return A matched DropperProfile if the permissions hit a threshold, null otherwise.
     */
    fun matchAgainstProfiles(permissions: List<String>): DropperProfile?
    
    /**
     * Interface for Pattern Learning.
     * Allows the system to dynamically update or add new dropper profiles 
     * based on cloud intelligence or zero-day heuristics.
     */
    suspend fun fetchLatestDropperPatterns()
}

class DropperProfileMatcherImpl : DropperProfileMatcher {

    // A mock database of known dropper profiles
    private val knownProfiles = mutableListOf(
        DropperProfile(
            profileId = "DP_BANKING_OVERLAY_01",
            description = "Banking Trojan leveraging SMS reading for OTPs and Screen Overlay for UI Redressing.",
            targetPermissions = listOf(
                "android.permission.RECEIVE_SMS",
                "android.permission.READ_SMS",
                "android.permission.SYSTEM_ALERT_WINDOW", // Screen Overlay
                "android.permission.BIND_ACCESSIBILITY_SERVICE"
            ),
            thresholdScore = 0.8f // Require at least 80% match of the target permissions
        )
    )

    override fun matchAgainstProfiles(permissions: List<String>): DropperProfile? {
        for (profile in knownProfiles) {
            val matchedCount = profile.targetPermissions.count { permissions.contains(it) }
            val matchRatio = if (profile.targetPermissions.isEmpty()) 0f else matchedCount.toFloat() / profile.targetPermissions.size
            
            if (matchRatio >= profile.thresholdScore) {
                return profile
            }
        }
        return null
    }

    override suspend fun fetchLatestDropperPatterns() {
        // Stub: Fetch new JSON definitions from SecureShield threat intel cloud
    }
}
