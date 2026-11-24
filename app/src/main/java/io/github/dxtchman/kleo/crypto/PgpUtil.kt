package io.github.dxtchman.kleo.crypto

import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.ECPublicBCPGKey
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.SignatureSubpacketTags
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPKeyRing
import org.bouncycastle.openpgp.PGPMarker
import org.bouncycastle.openpgp.PGPPBEEncryptedData
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.util.encoders.Hex
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.util.Date

/** Key usage flags as defined by RFC 4880 / RFC 9580. */
object KeyUsage {
    const val CERTIFY = 0x01
    const val SIGN = 0x02
    const val ENCRYPT_COMMS = 0x04
    const val ENCRYPT_STORAGE = 0x08
    const val AUTHENTICATE = 0x20
    const val ENCRYPT = ENCRYPT_COMMS or ENCRYPT_STORAGE

    fun describe(flags: Int): String = buildList {
        if (flags and CERTIFY != 0) add("Certify")
        if (flags and SIGN != 0) add("Sign")
        if (flags and ENCRYPT != 0) add("Encrypt")
        if (flags and AUTHENTICATE != 0) add("Authenticate")
    }.ifEmpty { listOf("—") }.joinToString(", ")
}

data class UserIdInfo(val raw: String, val name: String, val email: String?, val comment: String?)

data class SubkeyInfo(
    val keyId: Long,
    val fingerprint: String,
    val algorithm: String,
    val created: Date,
    val expires: Date?,
    val revoked: Boolean,
    val flags: Int,
    val hasSecret: Boolean,
    val isPrimary: Boolean,
) {
    val isExpired get() = expires?.before(Date()) == true
    val isUsable get() = !revoked && !isExpired
}

/** Everything the UI needs to know about a certificate (an OpenPGP key ring). */
data class CertInfo(
    val fingerprint: String,
    val keyId: Long,
    val userIds: List<UserIdInfo>,
    val created: Date,
    val expires: Date?,
    val revoked: Boolean,
    val isSecret: Boolean,
    val algorithm: String,
    val subkeys: List<SubkeyInfo>,
) {
    val primaryUid get() = userIds.firstOrNull()
    val name: String get() = primaryUid?.name?.takeIf { it.isNotBlank() } ?: primaryUid?.email ?: "(no user ID)"
    val email: String? get() = primaryUid?.email
    val isExpired get() = expires?.before(Date()) == true
    val isValid get() = !revoked && !isExpired
    val keyIdHex get() = fingerprint.takeLast(16)
    val label get() = buildString {
        append(name)
        email?.takeIf { it != name }?.let { append(" <").append(it).append('>') }
    }

    /** Can someone encrypt to this certificate? */
    val canEncrypt get() = isValid && subkeys.any { it.isUsable && it.flags and KeyUsage.ENCRYPT != 0 }

    /** Can we sign with this certificate (needs usable secret signing key material)? */
    val canSign get() = isSecret && isValid && subkeys.any { it.isUsable && it.hasSecret && it.flags and KeyUsage.SIGN != 0 }

    fun matches(query: String): Boolean {
        if (query.isBlank()) return true
        val q = query.trim().lowercase().removePrefix("0x").replace(" ", "")
        return userIds.any { it.raw.lowercase().contains(query.trim().lowercase()) } ||
            fingerprint.lowercase().contains(q) ||
            subkeys.any { it.fingerprint.lowercase().contains(q) }
    }
}

enum class DataKind { KEYS, MESSAGE, CLEARTEXT_SIGNED, DETACHED_SIGNATURE, PLAIN }

data class MessageScan(
    val encrypted: Boolean,
    val recipientKeyIds: List<Long>,
    val passwordEncrypted: Boolean,
)

object PgpUtil {

    private val ARMORED_KEY_BLOCK =
        Regex("-----BEGIN PGP (PUBLIC|PRIVATE) KEY BLOCK-----[\\s\\S]*?-----END PGP \\1 KEY BLOCK-----")
    private val USER_ID = Regex("^\\s*(.*?)\\s*(?:\\((.*)\\))?\\s*(?:<([^>]*)>)?\\s*$")
    private val BARE_EMAIL = Regex("^[^@\\s]+@[^@\\s]+$")

    // ---------------------------------------------------------------- parsing

    /** Parse every public and secret key ring found in [bytes] (ASCII-armoured or binary, possibly concatenated). */
    fun parseKeyRings(bytes: ByteArray): List<PGPKeyRing> {
        val result = mutableListOf<PGPKeyRing>()
        val text = runCatching { String(bytes, Charsets.UTF_8) }.getOrNull()
        if (text != null && text.contains("-----BEGIN PGP")) {
            ARMORED_KEY_BLOCK.findAll(text).forEach { block ->
                parseStream(ByteArrayInputStream(block.value.toByteArray(Charsets.UTF_8)), result)
            }
        } else {
            parseStream(ByteArrayInputStream(bytes), result)
        }
        return result
    }

    private fun parseStream(input: InputStream, out: MutableList<PGPKeyRing>) {
        try {
            val factory = BcPGPObjectFactory(PGPUtil.getDecoderStream(input))
            while (true) {
                val obj = try {
                    factory.nextObject()
                } catch (e: Exception) {
                    null
                } ?: break
                when (obj) {
                    is PGPSecretKeyRing -> out += obj
                    is PGPPublicKeyRing -> out += obj
                }
            }
        } catch (_: Exception) {
            // Not OpenPGP key material.
        }
    }

    /** Guess what kind of OpenPGP data [head] (the first bytes of a file or text) is. */
    fun sniff(head: ByteArray): DataKind {
        if (head.isEmpty()) return DataKind.PLAIN
        val text = String(head, 0, minOf(head.size, 64 * 1024), Charsets.ISO_8859_1)
        when {
            text.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----") ||
                text.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----") -> return DataKind.KEYS
            text.contains("-----BEGIN PGP SIGNED MESSAGE-----") -> return DataKind.CLEARTEXT_SIGNED
            text.contains("-----BEGIN PGP MESSAGE-----") -> return DataKind.MESSAGE
            text.contains("-----BEGIN PGP SIGNATURE-----") -> return DataKind.DETACHED_SIGNATURE
        }
        val b = head[0].toInt() and 0xFF
        if (b and 0x80 == 0) return DataKind.PLAIN
        val tag = if (b and 0x40 != 0) b and 0x3F else (b shr 2) and 0x0F
        return when (tag) {
            5, 6 -> if (parseKeyRings(head).isNotEmpty()) DataKind.KEYS else DataKind.PLAIN
            1, 3, 4, 8, 10, 18 -> DataKind.MESSAGE
            else -> DataKind.PLAIN
        }
    }

    /** Peek at the outer layer of an OpenPGP message to learn who it was encrypted for. */
    fun scanMessage(input: InputStream): MessageScan {
        try {
            val factory = BcPGPObjectFactory(PGPUtil.getDecoderStream(input))
            var obj: Any? = factory.nextObject()
            while (obj is PGPMarker) obj = factory.nextObject()
            if (obj is PGPEncryptedDataList) {
                val ids = mutableListOf<Long>()
                var pbe = false
                val it = obj.encryptedDataObjects
                while (it.hasNext()) {
                    when (val ed = it.next()) {
                        is PGPPublicKeyEncryptedData -> ids += ed.keyID
                        is PGPPBEEncryptedData -> pbe = true
                    }
                }
                return MessageScan(true, ids, pbe)
            }
        } catch (_: Exception) {
            // fall through
        }
        return MessageScan(false, emptyList(), false)
    }

    // ------------------------------------------------------------ conversion

    fun publicOf(ring: PGPKeyRing): PGPPublicKeyRing = when (ring) {
        is PGPPublicKeyRing -> ring
        is PGPSecretKeyRing -> PGPPublicKeyRing(ring.publicKeys.asSequence().toList())
        else -> error("Unknown key ring type")
    }

    fun armor(ring: PGPKeyRing): String {
        val bos = ByteArrayOutputStream()
        ArmoredOutputStream(bos).use { ring.encode(it) }
        return bos.toString("UTF-8")
    }

    fun fingerprint(key: PGPPublicKey): String = Hex.toHexString(key.fingerprint).uppercase()

    fun keyIdHex(keyId: Long): String = String.format("%016X", keyId)

    fun formatFingerprint(fpr: String): String {
        val groups = fpr.chunked(4)
        return if (groups.size == 10) {
            groups.take(5).joinToString(" ") + "  " + groups.drop(5).joinToString(" ")
        } else {
            groups.joinToString(" ")
        }
    }

    fun buildUserId(name: String, email: String): String {
        val n = name.trim()
        val e = email.trim()
        return when {
            n.isNotEmpty() && e.isNotEmpty() -> "$n <$e>"
            e.isNotEmpty() -> "<$e>"
            else -> n
        }
    }

    fun parseUserId(raw: String): UserIdInfo {
        if (BARE_EMAIL.matches(raw.trim())) return UserIdInfo(raw, "", raw.trim(), null)
        val m = USER_ID.matchEntire(raw)
        return if (m != null) {
            UserIdInfo(
                raw = raw,
                name = m.groupValues[1],
                email = m.groupValues[3].ifBlank { null },
                comment = m.groupValues[2].ifBlank { null },
            )
        } else {
            UserIdInfo(raw, raw, null, null)
        }
    }

    // ------------------------------------------------------------ secret keys

    /** True if any usable secret key in the ring is passphrase protected. */
    fun isProtected(ring: PGPSecretKeyRing): Boolean =
        ring.secretKeys.asSequence().any { !it.isPrivateKeyEmpty && it.s2KUsage != 0 }

    /** Check a passphrase against a secret key ring without changing anything. */
    fun checkPassphrase(ring: PGPSecretKeyRing, passphrase: String): Boolean {
        val key = ring.secretKeys.asSequence().firstOrNull { !it.isPrivateKeyEmpty && it.s2KUsage != 0 }
            ?: return true
        return try {
            val decryptor = BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider())
                .build(passphrase.toCharArray())
            key.extractPrivateKey(decryptor) != null
        } catch (e: Exception) {
            false
        }
    }

    // ------------------------------------------------------------- inspection

    fun inspect(ring: PGPKeyRing): CertInfo {
        val primary = ring.publicKey
        val secret = ring as? PGPSecretKeyRing
        val primaryId = primary.keyID

        val uids = primary.userIDs.asSequence().toList()
        val primaryUid = uids.firstOrNull { uid ->
            runCatching {
                primary.getSignaturesForID(uid).asSequence()
                    .any { it.keyID == primaryId && it.hashedSubPackets?.isPrimaryUserID == true }
            }.getOrDefault(false)
        }
        val orderedUids = (listOfNotNull(primaryUid) + uids.filter { it != primaryUid }).map(::parseUserId)

        val keys = ring.publicKeys.asSequence().map { key ->
            val flags = keyFlags(key, primaryId)
            SubkeyInfo(
                keyId = key.keyID,
                fingerprint = fingerprint(key),
                algorithm = algorithmName(key),
                created = key.creationTime,
                expires = expiry(key),
                revoked = key.hasRevocation(),
                flags = flags,
                hasSecret = secret?.getSecretKey(key.keyID)?.isPrivateKeyEmpty == false,
                isPrimary = key.isMasterKey,
            )
        }.toList()

        return CertInfo(
            fingerprint = fingerprint(primary),
            keyId = primaryId,
            userIds = orderedUids,
            created = primary.creationTime,
            expires = expiry(primary),
            revoked = primary.hasRevocation(),
            isSecret = secret != null && keys.any { it.hasSecret },
            algorithm = algorithmName(primary),
            subkeys = keys,
        )
    }

    private fun expiry(key: PGPPublicKey): Date? {
        val seconds = runCatching { key.validSeconds }.getOrDefault(0L)
        return if (seconds <= 0) null else Date(key.creationTime.time + seconds * 1000)
    }

    /** Key flags from the newest self-signature that carries them; falls back to the algorithm's abilities. */
    private fun keyFlags(key: PGPPublicKey, primaryId: Long): Int {
        val sig = key.signatures.asSequence()
            .filterIsInstance<PGPSignature>()
            .filter { it.keyID == primaryId }
            .filter { it.signatureType != PGPSignature.KEY_REVOCATION && it.signatureType != PGPSignature.SUBKEY_REVOCATION }
            .filter { it.hashedSubPackets?.hasSubpacket(SignatureSubpacketTags.KEY_FLAGS) == true }
            .maxByOrNull { it.creationTime }
        if (sig != null) return sig.hashedSubPackets.keyFlags
        // Old keys without key flags: infer from algorithm.
        var flags = 0
        if (key.isMasterKey) flags = flags or KeyUsage.CERTIFY or KeyUsage.SIGN
        if (key.isEncryptionKey) flags = flags or KeyUsage.ENCRYPT
        return flags
    }

    fun algorithmName(key: PGPPublicKey): String {
        val curve = runCatching { (key.publicKeyPacket.key as? ECPublicBCPGKey)?.curveOID?.id }
            .getOrNull()?.let(::curveName)
        return when (key.algorithm) {
            PublicKeyAlgorithmTags.RSA_GENERAL,
            PublicKeyAlgorithmTags.RSA_ENCRYPT,
            PublicKeyAlgorithmTags.RSA_SIGN -> "RSA ${key.bitStrength}"
            PublicKeyAlgorithmTags.DSA -> "DSA ${key.bitStrength}"
            PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT,
            PublicKeyAlgorithmTags.ELGAMAL_GENERAL -> "ElGamal ${key.bitStrength}"
            PublicKeyAlgorithmTags.ECDH -> "ECDH ${curve ?: ""}".trim()
            PublicKeyAlgorithmTags.ECDSA -> "ECDSA ${curve ?: ""}".trim()
            22 -> "EdDSA ${curve ?: "Ed25519"}"
            25 -> "X25519"
            26 -> "X448"
            27 -> "Ed25519"
            28 -> "Ed448"
            else -> "Algorithm ${key.algorithm}"
        }
    }

    private fun curveName(oid: String): String = when (oid) {
        "1.3.6.1.4.1.11591.15.1" -> "Ed25519"
        "1.3.6.1.4.1.3029.1.5.1" -> "Curve25519"
        "1.3.101.112" -> "Ed25519"
        "1.3.101.110" -> "Curve25519"
        "1.2.840.10045.3.1.7" -> "NIST P-256"
        "1.3.132.0.34" -> "NIST P-384"
        "1.3.132.0.35" -> "NIST P-521"
        "1.3.36.3.3.2.8.1.1.7" -> "brainpoolP256r1"
        "1.3.36.3.3.2.8.1.1.11" -> "brainpoolP384r1"
        "1.3.36.3.3.2.8.1.1.13" -> "brainpoolP512r1"
        "1.3.132.0.10" -> "secp256k1"
        else -> oid
    }
}
