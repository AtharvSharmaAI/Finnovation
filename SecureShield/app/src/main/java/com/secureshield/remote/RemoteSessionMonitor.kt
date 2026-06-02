package com.secureshield.remote

import com.secureshield.domain.model.RemoteAccessEvaluation
import com.secureshield.domain.model.RemoteSessionState

/**
 * Identifies remote or screen-sharing applications and monitors if they are actively casting.
 */
interface RemoteSessionMonitor {
    
    /**
     * Evaluates the current state of the device to detect active remote access.
     */
    suspend fun evaluateRemoteSessionState(): RemoteAccessEvaluation

    /**
     * Prompts the user with a critical warning if a protected app is opened while 
     * a remote session is active.
     */
    fun promptUserForConfirmation(appName: String, callback: (Boolean) -> Unit)
}

/**
 * Stubbed implementation demonstrating remote session monitoring logic.
 */
class RemoteSessionMonitorImpl : RemoteSessionMonitor {

    // Known list of legitimate RATs that could be abused
    private val KNOWN_REMOTE_APPS = setOf(
        "com.teamviewer.host.market",
        "com.anydesk.anydeskandroid",
        "com.microsoft.rdc.android"
    )

    override suspend fun evaluateRemoteSessionState(): RemoteAccessEvaluation {
        // Step 1: Detect installed/running remote apps
        // Real implementation would use PackageManager, UsageStatsManager, or AccessibilityService
        val installedApps = getStubbedRunningApps()
        val detectedRemoteApps = installedApps.intersect(KNOWN_REMOTE_APPS).toList()

        // Step 2: Check if actively casting
        // Real implementation would check MediaProjectionManager or DisplayManager
        val isActivelyCasting = checkStubbedMediaProjectionState()
        
        val state = when {
            detectedRemoteApps.isNotEmpty() && isActivelyCasting -> RemoteSessionState.ACTIVE_HIGH_RISK
            detectedRemoteApps.isNotEmpty() -> RemoteSessionState.ACTIVE_SAFE
            else -> RemoteSessionState.INACTIVE
        }

        return RemoteAccessEvaluation(
            state = state,
            activeRemoteApps = detectedRemoteApps,
            isScreenCasting = isActivelyCasting
        )
    }

    override fun promptUserForConfirmation(appName: String, callback: (Boolean) -> Unit) {
        // Stub: In a real app, this would show a full-screen system alert window
        // warning the user: "You have Anydesk open. Proceed to open SBI Banking App?"
        println("WARNING: Remote session active! Are you sure you want to open $appName?")
        // Simulating the user accepting the risk
        callback(true)
    }

    private fun getStubbedRunningApps(): List<String> {
        // Stubbed response
        return listOf("com.whatsapp", "com.anydesk.anydeskandroid", "com.android.chrome")
    }

    private fun checkStubbedMediaProjectionState(): Boolean {
        // Stubbed response simulating an active screen cast
        return true
    }
}
