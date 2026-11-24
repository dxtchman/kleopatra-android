package io.github.dxtchman.kleo.crypto

import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.pgpainless.PGPainless
import org.pgpainless.algorithm.DocumentSignatureType
import org.pgpainless.decryption_verification.ConsumerOptions
import org.pgpainless.encryption_signing.EncryptionOptions
import org.pgpainless.encryption_signing.ProducerOptions
import org.pgpainless.encryption_signing.SigningOptions
import org.pgpainless.key.generation.type.rsa.RsaLength
import org.pgpainless.key.protection.SecretKeyRingProtector
import org.pgpainless.util.Passphrase
import java.io.InputStream
import java.io.OutputStream
import java.util.Date

enum class KeyAlgorithm(val label: String) {
    CURVE25519("Curve25519 (recommended)"),
    RSA3072("RSA 3072"),
    RSA4096("RSA 4096"),
}

/** A key to decrypt with, together with the passphrase that unlocks it ("" = unprotected). */
data class UnlockedKey(val ring: PGPSecretKeyRing, val passphrase: String)

data class VerifyResult(
    val verified: List<PGPSignature>,
    val rejectedCount: Int,
)

/**
 * Thin wrapper around PGPainless for the actual cryptographic operations.
 * All functions block; call them off the main thread.
 */
object PgpOps {

    fun protector(passphrase: String): SecretKeyRingProtector =
        if (passphrase.isEmpty()) SecretKeyRingProtector.unprotectedKeys()
        else SecretKeyRingProtector.unlockAnyKeyWith(Passphrase.fromPassword(passphrase))

    // ------------------------------------------------------------- key mgmt

    fun generate(
        name: String,
        email: String,
        algorithm: KeyAlgorithm,
        expires: Date?,
        passphrase: String,
    ): PGPSecretKeyRing {
        require(passphrase.isNotEmpty()) { "A passphrase is required" }
        val userId = PgpUtil.buildUserId(name, email)
        val generator = PGPainless.generateKeyRing()
        var ring = when (algorithm) {
            KeyAlgorithm.CURVE25519 -> generator.modernKeyRing(userId, passphrase)
            KeyAlgorithm.RSA3072 -> generator.simpleRsaKeyRing(userId, RsaLength._3072, passphrase)
            KeyAlgorithm.RSA4096 -> generator.simpleRsaKeyRing(userId, RsaLength._4096, passphrase)
        }
        if (expires != null) {
            ring = PGPainless.modifyKeyRing(ring)
                .setExpirationDate(expires, protector(passphrase))
                .done()
        }
        return ring
    }

    fun changePassphrase(ring: PGPSecretKeyRing, old: String, new: String): PGPSecretKeyRing {
        val oldPass = if (old.isEmpty()) Passphrase.emptyPassphrase() else Passphrase.fromPassword(old)
        val newPass = if (new.isEmpty()) Passphrase.emptyPassphrase() else Passphrase.fromPassword(new)
        return PGPainless.modifyKeyRing(ring)
            .changePassphraseFromOldPassphrase(oldPass)
            .withSecureDefaultSettings()
            .toNewPassphrase(newPass)
            .done()
    }

    fun setExpiration(ring: PGPSecretKeyRing, passphrase: String, expires: Date?): PGPSecretKeyRing =
        PGPainless.modifyKeyRing(ring)
            .setExpirationDate(expires, protector(passphrase))
            .done()

    // ----------------------------------------------------- encrypt and sign

    /**
     * Encrypt and/or sign [input] into [output].
     * - recipients / password empty and signer set → inline-signed message (or cleartext if [cleartext])
     * - otherwise an encrypted message, signed if [signer] is set
     */
    fun encryptOrSign(
        input: InputStream,
        output: OutputStream,
        recipients: List<PGPPublicKeyRing>,
        password: String?,
        signer: UnlockedKey?,
        armor: Boolean,
        textMode: Boolean,
        cleartext: Boolean = false,
        fileName: String? = null,
    ) {
        val encrypt = recipients.isNotEmpty() || !password.isNullOrEmpty()
        require(encrypt || signer != null) { "Nothing to do: choose recipients or a signing key" }

        val sigType = if (textMode) DocumentSignatureType.CANONICAL_TEXT_DOCUMENT else DocumentSignatureType.BINARY_DOCUMENT

        val options: ProducerOptions = if (encrypt) {
            val enc = EncryptionOptions()
            recipients.forEach { enc.addRecipient(it) }
            if (!password.isNullOrEmpty()) enc.addMessagePassphrase(Passphrase.fromPassword(password))
            if (signer != null) {
                val sign = SigningOptions()
                sign.addInlineSignature(protector(signer.passphrase), signer.ring, sigType)
                ProducerOptions.signAndEncrypt(enc, sign)
            } else {
                ProducerOptions.encrypt(enc)
            }
        } else {
            val sign = SigningOptions()
            if (cleartext) {
                sign.addDetachedSignature(protector(signer!!.passphrase), signer.ring, DocumentSignatureType.CANONICAL_TEXT_DOCUMENT)
                ProducerOptions.sign(sign)
            } else {
                sign.addInlineSignature(protector(signer!!.passphrase), signer.ring, sigType)
                ProducerOptions.sign(sign)
            }
        }

        options.setAsciiArmor(armor || cleartext)
        if (cleartext && !encrypt) options.setCleartextSigned()
        if (fileName != null) options.setFileName(fileName)

        val stream = PGPainless.encryptAndOrSign()
            .onOutputStream(output)
            .withOptions(options)
        input.copyTo(stream)
        stream.close()
    }

    // ---------------------------------------------------- decrypt and verify

    fun decryptOrVerify(
        input: InputStream,
        output: OutputStream,
        keys: List<UnlockedKey>,
        verificationCerts: List<PGPPublicKeyRing>,
        messagePassword: String?,
    ): VerifyResult {
        val options = ConsumerOptions.get()
        keys.forEach { options.addDecryptionKey(it.ring, protector(it.passphrase)) }
        verificationCerts.forEach { options.addVerificationCert(it) }
        if (!messagePassword.isNullOrEmpty()) options.addMessagePassphrase(Passphrase.fromPassword(messagePassword))

        val stream = PGPainless.decryptAndOrVerify()
            .onInputStream(input)
            .withOptions(options)
        stream.copyTo(output)
        stream.close()

        val metadata = stream.metadata
        return VerifyResult(
            verified = metadata.verifiedSignatures.map { it.signature },
            rejectedCount = metadata.rejectedSignatures.size,
        )
    }

    /** Verify a detached signature (e.g. `file.sig`) over [data]. */
    fun verifyDetached(
        data: InputStream,
        signature: InputStream,
        verificationCerts: List<PGPPublicKeyRing>,
    ): VerifyResult {
        val options = ConsumerOptions.get()
        verificationCerts.forEach { options.addVerificationCert(it) }
        options.addVerificationOfDetachedSignatures(signature)

        val stream = PGPainless.decryptAndOrVerify()
            .onInputStream(data)
            .withOptions(options)
        val sink = object : OutputStream() {
            override fun write(b: Int) = Unit
            override fun write(b: ByteArray, off: Int, len: Int) = Unit
        }
        stream.copyTo(sink)
        stream.close()

        val metadata = stream.metadata
        return VerifyResult(
            verified = metadata.verifiedSignatures.map { it.signature },
            rejectedCount = metadata.rejectedSignatures.size,
        )
    }

    /** Turn library exceptions into something a person can act on. */
    fun friendlyError(e: Throwable): String {
        val name = e::class.java.simpleName
        val msg = e.message.orEmpty()
        return when {
            name == "WrongPassphraseException" -> "Wrong passphrase."
            name == "MissingDecryptionMethodException" ->
                "None of your secret keys can decrypt this message."
            name == "UnacceptableEncryptionKeyException" || name == "UnacceptableRecipientKeyException" ->
                "A recipient's certificate can't be used for encryption (expired, revoked or no encryption subkey)."
            name == "UnacceptableSigningKeyException" ->
                "This key can't be used for signing (expired, revoked or no signing subkey)."
            name == "MalformedOpenPgpMessageException" || msg.contains("invalid armor", true) ->
                "This doesn't look like a valid OpenPGP message."
            name == "ModificationDetectionException" ->
                "The message was modified or is corrupt (integrity check failed)."
            name == "MessageNotIntegrityProtectedException" ->
                "The message isn't integrity protected and was rejected for safety."
            msg.isNotBlank() -> msg
            else -> name
        }
    }
}
