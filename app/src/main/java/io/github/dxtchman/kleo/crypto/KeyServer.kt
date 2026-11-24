package io.github.dxtchman.kleo.crypto

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.bouncycastle.openpgp.PGPKeyRing
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.security.MessageDigest

data class LookupHit(val source: String, val ring: PGPKeyRing, val info: CertInfo)

data class LookupOutcome(val hits: List<LookupHit>, val errors: List<String>)

data class PublishResult(val token: String, val fingerprint: String, val addressStatus: Map<String, String>)

/**
 * Certificate discovery the way Kleopatra does it: Web Key Directory (WKD) for e-mail
 * addresses, keys.openpgp.org (VKS) and keyserver.ubuntu.com (HKP) as keyservers.
 */
object KeyServer {

    private const val VKS = "https://keys.openpgp.org"
    private const val HKP = "https://keyserver.ubuntu.com"
    private val HEX = Regex("^(0x)?[0-9a-fA-F]+$")

    suspend fun lookup(rawQuery: String): LookupOutcome = withContext(Dispatchers.IO) {
        val query = rawQuery.trim()
        require(query.isNotEmpty()) { "Enter an e-mail address, fingerprint or key ID" }
        val compact = query.replace(" ", "")
        val hits = mutableListOf<LookupHit>()
        val errors = mutableListOf<String>()

        fun collect(source: String, reportErrors: Boolean = true, block: () -> ByteArray?) {
            try {
                block()?.let { bytes ->
                    PgpUtil.parseKeyRings(bytes).forEach { ring ->
                        val pub = PgpUtil.publicOf(ring)
                        hits += LookupHit(source, pub, PgpUtil.inspect(pub))
                    }
                }
            } catch (e: Exception) {
                if (reportErrors) errors += "$source: ${e.message ?: e::class.java.simpleName}"
            }
        }

        when {
            query.contains('@') -> {
                val email = query.removePrefix("<").removeSuffix(">")
                collect("Web Key Directory", reportErrors = false) { wkd(email) }
                collect("keys.openpgp.org") { get("$VKS/vks/v1/by-email/${enc(email)}") }
                if (hits.isEmpty()) collect("keyserver.ubuntu.com") { hkpGet(email) }
            }
            HEX.matches(compact) && compact.removePrefix("0x").length in setOf(16, 40, 64) -> {
                val hex = compact.removePrefix("0x").uppercase()
                val path = if (hex.length == 16) "by-keyid" else "by-fingerprint"
                collect("keys.openpgp.org") { get("$VKS/vks/v1/$path/$hex") }
                if (hits.isEmpty()) collect("keyserver.ubuntu.com") { hkpGet("0x$hex") }
            }
            else -> collect("keyserver.ubuntu.com") { hkpGet(query) }
        }

        val unique = hits.groupBy { it.info.fingerprint }.map { (_, sameKey) -> sameKey.first() }
        LookupOutcome(unique, errors)
    }

    /** Upload a certificate to keys.openpgp.org. */
    suspend fun publish(armored: String): PublishResult = withContext(Dispatchers.IO) {
        val body = JSONObject().put("keytext", armored).toString()
        parsePublish(JSONObject(post("$VKS/vks/v1/upload", body)))
    }

    /** Ask keys.openpgp.org to send verification e-mails so the user IDs become searchable. */
    suspend fun requestVerification(token: String, addresses: List<String>): PublishResult =
        withContext(Dispatchers.IO) {
            val body = JSONObject()
                .put("token", token)
                .put("addresses", JSONArray(addresses))
                .toString()
            parsePublish(JSONObject(post("$VKS/vks/v1/request-verify", body)))
        }

    private fun parsePublish(json: JSONObject): PublishResult {
        val status = json.optJSONObject("status")
        val map = buildMap {
            status?.let { st -> st.keys().forEach { key -> put(key, st.optString(key)) } }
        }
        return PublishResult(json.optString("token"), json.optString("key_fpr"), map)
    }

    // ------------------------------------------------------------------ WKD

    private fun wkd(email: String): ByteArray? {
        val at = email.lastIndexOf('@')
        if (at <= 0) return null
        val local = email.substring(0, at)
        val domain = email.substring(at + 1).lowercase()
        val hash = zBase32(MessageDigest.getInstance("SHA-1").digest(local.lowercase().toByteArray()))
        val l = enc(local)
        val advanced = "https://openpgpkey.$domain/.well-known/openpgpkey/$domain/hu/$hash?l=$l"
        val direct = "https://$domain/.well-known/openpgpkey/hu/$hash?l=$l"
        return runCatching { get(advanced) }.getOrNull() ?: get(direct)
    }

    private fun zBase32(data: ByteArray): String {
        val alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"
        val sb = StringBuilder()
        var buffer = 0
        var bits = 0
        for (b in data) {
            buffer = (buffer shl 8) or (b.toInt() and 0xFF)
            bits += 8
            while (bits >= 5) {
                sb.append(alphabet[(buffer shr (bits - 5)) and 0x1F])
                bits -= 5
            }
        }
        if (bits > 0) sb.append(alphabet[(buffer shl (5 - bits)) and 0x1F])
        return sb.toString()
    }

    // ------------------------------------------------------------------ HTTP

    private fun hkpGet(search: String): ByteArray? =
        get("$HKP/pks/lookup?op=get&options=mr&search=${enc(search)}")

    private fun enc(s: String) = URLEncoder.encode(s, "UTF-8")

    /** GET returning the body, or null on 404. */
    private fun get(url: String): ByteArray? {
        val conn = URL(url).openConnection() as HttpURLConnection
        try {
            conn.connectTimeout = 15_000
            conn.readTimeout = 20_000
            conn.setRequestProperty("User-Agent", "Kleo-Android")
            return when (val code = conn.responseCode) {
                in 200..299 -> conn.inputStream.use { it.readBytes() }
                404 -> null
                else -> throw IOException("HTTP $code")
            }
        } finally {
            conn.disconnect()
        }
    }

    private fun post(url: String, json: String): String {
        val conn = URL(url).openConnection() as HttpURLConnection
        try {
            conn.requestMethod = "POST"
            conn.doOutput = true
            conn.connectTimeout = 15_000
            conn.readTimeout = 30_000
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("User-Agent", "Kleo-Android")
            conn.outputStream.use { it.write(json.toByteArray()) }
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val body = stream?.use { it.readBytes().toString(Charsets.UTF_8) }.orEmpty()
            if (code !in 200..299) {
                val error = runCatching { JSONObject(body).optString("error") }.getOrNull()
                throw IOException(error?.takeIf { it.isNotBlank() } ?: "HTTP $code")
            }
            return body
        } finally {
            conn.disconnect()
        }
    }
}
