package com.secureshield.apk

import kotlinx.coroutines.flow.Flow
import java.io.File

/**
 * Interface representing the detection mechanism for APK files arriving on the device.
 */
interface ApkDownloadObserver {

    /**
     * Starts observing the system for incoming APK files or install sessions.
     */
    fun startObserving()

    /**
     * Stops the observation.
     */
    fun stopObserving()

    /**
     * Emits a Flow of files whenever a new APK is detected on the filesystem 
     * (e.g., via FileObserver on the Downloads folder).
     */
    fun observeDownloadedApks(): Flow<File>

    /**
     * Emits a Flow of package names when an installation session is initiated 
     * (e.g., via PackageInstaller.SessionCallback).
     * 
     * Note: Intercepting the installation before it completes might require 
     * AccessibilityService if the app is not a Device/Profile Owner.
     */
    fun observeInstallSessions(): Flow<String>
    
    /**
     * Executes the block action for a malicious APK installation attempt.
     */
    fun blockInstallation(packageName: String)
    
    /**
     * Executes the allow action for a verified safe APK.
     */
    fun allowInstallation(packageName: String)
}
