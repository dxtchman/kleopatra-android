package io.github.dxtchman.kleo.crypto

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.bouncycastle.openpgp.PGPKeyRing
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import java.io.File

data class ImportResult(
    val new: Int = 0,
    val updated: Int = 0,
    val unchanged: Int = 0,
    val secret: Int = 0,
    val fingerprints: List<String> = emptyList(),
) {
    val total get() = new + updated + unchanged

    fun summary(): String = if (total == 0) {
        "No certificates found."
    } else buildString {
        append("Imported $total certificate")
        if (total != 1) append('s')
        val parts = buildList {
            if (new > 0) add("$new new")
            if (updated > 0) add("$updated updated")
            if (unchanged > 0) add("$unchanged unchanged")
            if (secret > 0) add("$secret with secret key")
        }
        if (parts.isNotEmpty()) append(" (").append(parts.joinToString(", ")).append(')')
    }
}

/**
 * The local keyring. Each certificate is stored as one binary file in the app's private
 * storage: `<FINGERPRINT>.pub` for public certificates, `<FINGERPRINT>.sec` when we hold
 * the secret key. Secret keys stay protected by their own OpenPGP passphrase.
 */
class KeyRepository(context: Context) {

    private val dir = File(context.filesDir, "keyring").apply { mkdirs() }
    private val mutex = Mutex()
    private val rings = LinkedHashMap<String, PGPKeyRing>()

    private val _certs = MutableStateFlow<List<CertInfo>>(emptyList())
    val certs: StateFlow<List<CertInfo>> = _certs.asStateFlow()

    private val _loaded = MutableStateFlow(false)
    val loaded: StateFlow<Boolean> = _loaded.asStateFlow()

    suspend fun load() = withContext(Dispatchers.IO) {
        mutex.withLock {
            val loadedRings = LinkedHashMap<String, PGPKeyRing>()
            dir.listFiles()?.filter { it.extension == "pub" || it.extension == "sec" }?.forEach { file ->
                PgpUtil.parseKeyRings(file.readBytes()).firstOrNull()?.let { ring ->
                    val fpr = PgpUtil.fingerprint(ring.publicKey)
                    // A .sec file wins over a stale .pub one.
                    if (loadedRings[fpr] !is PGPSecretKeyRing) loadedRings[fpr] = ring
                }
            }
            synchronized(rings) {
                rings.clear()
                rings.putAll(loadedRings)
            }
            publish()
        }
        _loaded.value = true
    }

    // ----------------------------------------------------------------- lookup

    fun ring(fpr: String): PGPKeyRing? = synchronized(rings) { rings[fpr] }

    fun secretRing(fpr: String): PGPSecretKeyRing? = ring(fpr) as? PGPSecretKeyRing

    fun publicRing(fpr: String): PGPPublicKeyRing? = ring(fpr)?.let(PgpUtil::publicOf)

    fun cert(fpr: String): CertInfo? = _certs.value.firstOrNull { it.fingerprint == fpr }

    fun allPublicRings(): List<PGPPublicKeyRing> = synchronized(rings) { rings.values.map(PgpUtil::publicOf) }

    fun allSecretRings(): List<PGPSecretKeyRing> = synchronized(rings) { rings.values.filterIsInstance<PGPSecretKeyRing>() }

    /** Find the certificate that contains the (sub)key with this key ID. */
    fun certForKeyId(keyId: Long): CertInfo? =
        _certs.value.firstOrNull { cert -> cert.subkeys.any { it.keyId == keyId } }

    fun secretRingForKeyId(keyId: Long): PGPSecretKeyRing? = synchronized(rings) {
        rings.values.filterIsInstance<PGPSecretKeyRing>().firstOrNull { ring ->
            ring.getSecretKey(keyId)?.isPrivateKeyEmpty == false
        }
    }

    // ------------------------------------------------------------- mutations

    suspend fun import(bytes: ByteArray): ImportResult = withContext(Dispatchers.IO) {
        val parsed = PgpUtil.parseKeyRings(bytes)
        mutex.withLock {
            var new = 0
            var updated = 0
            var unchanged = 0
            var secret = 0
            val fprs = mutableListOf<String>()
            for (incoming in parsed) {
                val fpr = PgpUtil.fingerprint(incoming.publicKey)
                val existing = synchronized(rings) { rings[fpr] }
                val (merged, status) = merge(existing, incoming)
                when (status) {
                    MergeStatus.NEW -> new++
                    MergeStatus.UPDATED -> updated++
                    MergeStatus.UNCHANGED -> unchanged++
                }
                if (incoming is PGPSecretKeyRing) secret++
                if (status != MergeStatus.UNCHANGED) write(fpr, merged)
                fprs += fpr
            }
            publish()
            ImportResult(new, updated, unchanged, secret, fprs.distinct())
        }
    }

    /** Add or replace a key ring we produced ourselves (key generation, passphrase change, ...). */
    suspend fun store(ring: PGPKeyRing): String = withContext(Dispatchers.IO) {
        mutex.withLock {
            val fpr = PgpUtil.fingerprint(ring.publicKey)
            write(fpr, ring)
            publish()
            fpr
        }
    }

    suspend fun delete(fpr: String) = withContext(Dispatchers.IO) {
        mutex.withLock {
            File(dir, "$fpr.pub").delete()
            File(dir, "$fpr.sec").delete()
            synchronized(rings) { rings.remove(fpr) }
            publish()
        }
    }

    // ---------------------------------------------------------------- helpers

    private enum class MergeStatus { NEW, UPDATED, UNCHANGED }

    private fun merge(existing: PGPKeyRing?, incoming: PGPKeyRing): Pair<PGPKeyRing, MergeStatus> {
        if (existing == null) return incoming to MergeStatus.NEW

        if (incoming is PGPSecretKeyRing) {
            if (existing is PGPSecretKeyRing && existing.encoded.contentEquals(incoming.encoded)) {
                return existing to MergeStatus.UNCHANGED
            }
            // Keep any newer public parts we already had (e.g. refreshed from a keyserver).
            val joinedPub = runCatching {
                PGPPublicKeyRing.join(PgpUtil.publicOf(incoming), PgpUtil.publicOf(existing))
            }.getOrNull()
            val merged = joinedPub?.let { runCatching { PGPSecretKeyRing.replacePublicKeys(incoming, it) }.getOrNull() }
            return (merged ?: incoming) to MergeStatus.UPDATED
        }

        val incomingPub = incoming as PGPPublicKeyRing
        val existingPub = PgpUtil.publicOf(existing)
        val joined = runCatching { PGPPublicKeyRing.join(existingPub, incomingPub) }.getOrNull()
            ?: return existing to MergeStatus.UNCHANGED
        if (joined.encoded.contentEquals(existingPub.encoded)) return existing to MergeStatus.UNCHANGED

        if (existing is PGPSecretKeyRing) {
            val merged = runCatching { PGPSecretKeyRing.replacePublicKeys(existing, joined) }.getOrNull()
                ?: return existing to MergeStatus.UNCHANGED
            return merged to MergeStatus.UPDATED
        }
        return joined to MergeStatus.UPDATED
    }

    private fun write(fpr: String, ring: PGPKeyRing) {
        val ext = if (ring is PGPSecretKeyRing) "sec" else "pub"
        val target = File(dir, "$fpr.$ext")
        val tmp = File(dir, "$fpr.$ext.tmp")
        tmp.writeBytes(ring.encoded)
        if (!tmp.renameTo(target)) {
            target.delete()
            tmp.renameTo(target)
        }
        // Drop the other variant so we never have both.
        File(dir, "$fpr.${if (ext == "sec") "pub" else "sec"}").delete()
        synchronized(rings) { rings[fpr] = ring }
    }

    private fun publish() {
        val infos = synchronized(rings) { rings.values.toList() }
            .mapNotNull { runCatching { PgpUtil.inspect(it) }.getOrNull() }
            .sortedWith(compareByDescending<CertInfo> { it.isSecret }.thenBy { it.name.lowercase() })
        _certs.value = infos
    }
}
