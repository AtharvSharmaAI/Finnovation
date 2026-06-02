package com.secureshield.behavior

import com.secureshield.domain.model.BehaviorThreatScore
import com.secureshield.domain.model.ThreatStatus

/**
 * Monitors apps after installation for dangerous runtime behaviors and permission combinations.
 */
interface RuntimeBehaviorMonitor {
    
    /**
     * Scans a newly installed or updated application.
     */
    suspend fun scanInstalledApp(packageName: String): BehaviorThreatScore

    /**
     * Triggers a high-priority system alert marking the app as a suspicious dropper.
     */
    fun flagAsDropper(packageName: String, reason: String)
}

class RuntimeBehaviorMonitorImpl(
    private val profileMatcher: DropperProfileMatcher
) : RuntimeBehaviorMonitor {

    override suspend fun scanInstalledApp(packageName: String): BehaviorThreatScore {
        // 1. Stubbed Extraction: Read Permissions using PackageManager
        // val packageInfo = packageManager.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS)
        // val requestedPermissions = packageInfo.requestedPermissions?.toList() ?: emptyList()
        
        // Simulating an app requesting the dangerous SMS + Overlay combination
        val stubbedPermissions = listOf(
            "android.permission.INTERNET",
            "android.permission.RECEIVE_SMS",
            "android.permission.SYSTEM_ALERT_WINDOW"
        )

        // 2. Explicit Check: SMS + Overlay combination (Often used by banking malware to steal OTP and draw fake screens)
        val hasSms = stubbedPermissions.contains("android.permission.RECEIVE_SMS") || 
                     stubbedPermissions.contains("android.permission.READ_SMS")
        val hasOverlay = stubbedPermissions.contains("android.permission.SYSTEM_ALERT_WINDOW")
        
        var isDropper = false
        var riskScore = 0.1f
        var status = ThreatStatus.SAFE

        if (hasSms && hasOverlay) {
            isDropper = true
            riskScore = 0.95f
            status = ThreatStatus.BLOCKED
            
            // Trigger alert
            flagAsDropper(packageName, "Critical Permission Combination Detected: SMS + Screen Overlay")
        }

        // 3. Match against dynamic dropper profiles
        val matchedProfile = profileMatcher.matchAgainstProfiles(stubbedPermissions)
        if (matchedProfile != null && !isDropper) {
            isDropper = true
            riskScore = 0.85f
            status = ThreatStatus.BLOCKED
            flagAsDropper(packageName, "Matched known dropper profile: ${matchedProfile.description}")
        }

        return BehaviorThreatScore(
            packageName = packageName,
            isDropper = isDropper,
            matchedProfile = matchedProfile,
            riskScore = riskScore,
            status = status
        )
    }

    override fun flagAsDropper(packageName: String, reason: String) {
        // In a real implementation, this would trigger a Notification or a full-screen Intent
        println("ALERT! Package $packageName flagged as Dropper. Reason: $reason")
    }
}
