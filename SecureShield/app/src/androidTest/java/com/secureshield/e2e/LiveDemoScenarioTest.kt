package com.secureshield.e2e

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.secureshield.domain.model.ThreatStatus
import com.secureshield.gateway.UrlThreatAnalyzerImpl
import com.secureshield.apk.SignatureVerifierImpl
import com.secureshield.human.NlpMessageAnalyzerImpl
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * End-to-End Test simulating the "Live Demo Scenario":
 * Fake SMS Received -> Link Flagged -> APK Download Intercepted -> App Blocked
 */
@RunWith(AndroidJUnit4::class)
class LiveDemoScenarioTest {

    private lateinit var nlpMessageAnalyzer: NlpMessageAnalyzerImpl
    private lateinit var urlThreatAnalyzer: UrlThreatAnalyzerImpl
    private lateinit var signatureVerifier: SignatureVerifierImpl

    @Before
    fun setup() {
        nlpMessageAnalyzer = NlpMessageAnalyzerImpl()
        urlThreatAnalyzer = UrlThreatAnalyzerImpl()
        signatureVerifier = SignatureVerifierImpl()
    }

    @Test
    fun testLiveDemo_SmsToApkBlockFlow() = runBlocking {
        println("--- Starting Live Demo Scenario E2E Test ---")

        // STEP 1: Fake SMS Received
        // Simulate a broadcast receiver passing message contents to the NLP analyzer
        val senderId = "+18005550199" // Mock bad number
        val smsContent = "URGENT: Your SBI Account is suspended. Verify OTP and login here: https://bank-verify-account.net/login"
        
        val smsScore = nlpMessageAnalyzer.analyzeMessage(
            senderId = senderId,
            content = smsContent,
            isKnownFraud = true
        )
        
        println("Step 1 -> SMS Score: ${smsScore.finalScore}, Status: ${smsScore.status}")
        assertEquals(ThreatStatus.BLOCKED, smsScore.status)
        assertTrue("OTP/Urgency pattern should be detected", smsScore.nlpSignals?.otpRequestDetected == true)

        // STEP 2: Link Flagged at Gateway
        // Simulate the user clicking the link despite the warning
        val phishingUrl = "https://bank-verify-account.net/login"
        
        val urlScore = urlThreatAnalyzer.analyzeUrl(phishingUrl)
        
        println("Step 2 -> URL Score: ${urlScore.finalScore}, Status: ${urlScore.status}")
        assertEquals(ThreatStatus.BLOCKED, urlScore.status)
        assertEquals("STATIC_BLACKLIST_MATCH", urlScore.ruleMatched)

        // STEP 3: APK Download Detected
        // Simulate a drive-by download bypassing the browser warning
        val fakeApkFile = File(InstrumentationRegistry.getInstrumentation().targetContext.cacheDir, "fake_update.apk")
        if (!fakeApkFile.exists()) {
            fakeApkFile.createNewFile()
        }
        
        // Step 4: Fake App Blocked
        // SignatureVerifier intercepts the APK prior to installation
        val apkScore = signatureVerifier.verifyApk(fakeApkFile)
        
        println("Step 3 & 4 -> APK Final Score: ${apkScore.finalScore}, Status: ${apkScore.status}")
        assertEquals(ThreatStatus.BLOCKED, apkScore.status)
        assertTrue("Signature should be invalid", !apkScore.isSignatureVerified)
        assertTrue("Dangerous permissions should be flagged", apkScore.dangerousPermissionsCount > 0)
        
        // Clean up
        fakeApkFile.delete()

        println("--- Live Demo Scenario E2E Test Passed: Threat Neutralized ---")
    }
}
