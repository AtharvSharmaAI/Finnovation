package com.secureshield.human

/**
 * Interface for looking up phone numbers or sender IDs against a live fraud database.
 */
interface FraudDatabaseRepository {

    /**
     * Checks if the given sender ID (phone number or name) is a known fraudulent entity.
     * 
     * @param senderId The phone number or sender string to check.
     * @return True if the sender is flagged in the database.
     */
    suspend fun isKnownFraudNumber(senderId: String): Boolean
    
    /**
     * Fetches the latest fraud database definitions from the secure server.
     */
    suspend fun syncFraudDatabase()
}

/**
 * Stubbed implementation of the Fraud Database Repository.
 */
class FraudDatabaseRepositoryImpl : FraudDatabaseRepository {
    
    private val stubbedFraudNumbers = setOf(
        "+18005550199",
        "+447700900077",
        "BANK-URGENT",
        "SBI-ALERT"
    )

    override suspend fun isKnownFraudNumber(senderId: String): Boolean {
        // Simple mock lookup
        return stubbedFraudNumbers.contains(senderId.uppercase())
    }

    override suspend fun syncFraudDatabase() {
        // Mock sync
    }
}
