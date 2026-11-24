package io.github.dxtchman.kleo.ui

import android.app.Application
import android.content.Intent
import android.net.Uri
import android.provider.DocumentsContract
import android.provider.OpenableColumns
import android.util.Log
import androidx.core.content.IntentCompat
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import io.github.dxtchman.kleo.KleoApp
import io.github.dxtchman.kleo.crypto.CertInfo
import io.github.dxtchman.kleo.crypto.DataKind
import io.github.dxtchman.kleo.crypto.ImportResult
import io.github.dxtchman.kleo.crypto.KeyAlgorithm
import io.github.dxtchman.kleo.crypto.KeyServer
import io.github.dxtchman.kleo.crypto.LookupHit
import io.github.dxtchman.kleo.crypto.PgpOps
import io.github.dxtchman.kleo.crypto.PgpUtil
import io.github.dxtchman.kleo.crypto.PublishResult
import io.github.dxtchman.kleo.crypto.UnlockedKey
import io.github.dxtchman.kleo.crypto.VerifyResult
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.bouncycastle.openpgp.PGPPublicKeyRing
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.text.DateFormat
import java.util.Date
import java.util.concurrent.ConcurrentHashMap

object Routes {
    const val CERTS = "certs"
    const val NOTEPAD = "notepad"
    const val FILES = "files"
    const val NEW_KEY = "newkey"
    const val LOOKUP = "lookup"
    const val CERT = "cert/{fpr}"
    fun cert(fpr: String) = "cert/$fpr"
}

enum class LineKind { OK, WARN, ERROR, INFO }

data class ResultLine(val kind: LineKind, val text: String)

data class OpResult(val title: String, val lines: List<ResultLine>) {
    val kind: LineKind
        get() = when {
            lines.any { it.kind == LineKind.ERROR } -> LineKind.ERROR
            lines.any { it.kind == LineKind.WARN } -> LineKind.WARN
            lines.any { it.kind == LineKind.OK } -> LineKind.OK
            else -> LineKind.INFO
        }

    companion object {
        fun error(title: String, text: String) = OpResult(title, listOf(ResultLine(LineKind.ERROR, text)))
    }
}

data class PickedFile(val uri: Uri, val name: String, val size: Long?, val kind: DataKind)

/** Options chosen in the Sign / Encrypt sheet. */
data class EncryptRequest(
    val myFingerprint: String?,
    val sign: Boolean,
    val encryptToSelf: Boolean,
    val recipients: List<String>,
    val password: String?,
    val armor: Boolean = true,
) {
    val encrypts get() = recipients.isNotEmpty() || (encryptToSelf && myFingerprint != null) || !password.isNullOrEmpty()
}

class PassphraseRequest(
    val title: String,
    val message: String,
    /** When set, the dialog checks the passphrase against this secret key before accepting it. */
    val fingerprint: String?,
    internal val result: CompletableDeferred<Pair<String, Boolean>?> = CompletableDeferred(),
) {
    fun submit(passphrase: String, remember: Boolean) = result.complete(passphrase to remember)
    fun cancel() = result.complete(null)
}

data class LookupState(
    val searching: Boolean = false,
    val searched: Boolean = false,
    val hits: List<LookupHit> = emptyList(),
    val errors: List<String> = emptyList(),
)

data class PublishState(val fingerprint: String, val result: PublishResult)

class AppViewModel(app: Application) : AndroidViewModel(app) {

    private val repo = (app as KleoApp).keys
    private val resolver get() = getApplication<Application>().contentResolver
    private val passCache = ConcurrentHashMap<String, String>()

    val certs: StateFlow<List<CertInfo>> = repo.certs
    val loaded: StateFlow<Boolean> = repo.loaded

    private val _messages = Channel<String>(Channel.BUFFERED)
    val messages = _messages.receiveAsFlow()

    private val _nav = Channel<String>(Channel.BUFFERED)
    val navEvents = _nav.receiveAsFlow()

    private val _busy = MutableStateFlow<String?>(null)
    val busy = _busy.asStateFlow()

    private val _passphraseRequest = MutableStateFlow<PassphraseRequest?>(null)
    val passphraseRequest = _passphraseRequest.asStateFlow()

    val notepadText = MutableStateFlow("")
    val notepadResult = MutableStateFlow<OpResult?>(null)

    val pickedFile = MutableStateFlow<PickedFile?>(null)
    val filesResult = MutableStateFlow<OpResult?>(null)

    private val _lookup = MutableStateFlow(LookupState())
    val lookupState = _lookup.asStateFlow()

    private val _publish = MutableStateFlow<PublishState?>(null)
    val publish = _publish.asStateFlow()

    /** Options waiting for the user to choose where to save the encrypted file. */
    var pendingFileRequest: EncryptRequest? = null

    /** The last options used in the Sign / Encrypt sheet, to prefill it next time. */
    var lastEncrypt: EncryptRequest? = null
        private set

    // ================================================================ plumbing

    private fun say(text: String) {
        _messages.trySend(text)
    }

    private fun navigate(route: String) {
        _nav.trySend(route)
    }

    private fun launchOp(
        label: String,
        onError: (String) -> Unit = ::say,
        block: suspend () -> Unit,
    ) = viewModelScope.launch {
        _busy.value = label
        try {
            repo.loaded.first { it }
            block()
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            Log.w(TAG, "$label failed", e)
            onError(PgpOps.friendlyError(e))
        } finally {
            _busy.value = null
        }
    }

    /** Get the passphrase for a secret key: "" if unprotected, cached if known, otherwise ask. null = cancelled. */
    private suspend fun unlock(fpr: String, purpose: String): String? {
        val ring = repo.secretRing(fpr) ?: return null
        if (!PgpUtil.isProtected(ring)) return ""
        passCache[fpr]?.let { return it }
        val cert = repo.cert(fpr)
        val who = cert?.let { "${it.label}\n${PgpUtil.formatFingerprint(it.keyIdHex)}" } ?: fpr
        val answer = ask(PassphraseRequest("Enter passphrase", "$purpose\n\n$who", fpr)) ?: return null
        if (answer.second) passCache[fpr] = answer.first
        return answer.first
    }

    private suspend fun askPassword(title: String, message: String): String? =
        ask(PassphraseRequest(title, message, null))?.first

    private suspend fun ask(request: PassphraseRequest): Pair<String, Boolean>? {
        _passphraseRequest.value = request
        return try {
            request.result.await()
        } finally {
            _passphraseRequest.value = null
        }
    }

    /** Used by the passphrase dialog to reject a wrong passphrase before closing. */
    suspend fun checkPassphrase(fpr: String, passphrase: String): Boolean = withContext(Dispatchers.Default) {
        repo.secretRing(fpr)?.let { PgpUtil.checkPassphrase(it, passphrase) } ?: false
    }

    fun forgetPassphrases() {
        passCache.clear()
        say("Cached passphrases cleared")
    }

    fun hasCachedPassphrases() = passCache.isNotEmpty()

    fun isProtected(fpr: String): Boolean = repo.secretRing(fpr)?.let(PgpUtil::isProtected) ?: false

    // ============================================================ certificates

    fun importText(text: String) = launchOp("Importing…") {
        val r = repo.import(text.toByteArray())
        say(r.summary())
    }

    fun importUris(uris: List<Uri>) = launchOp("Importing…") {
        var total = ImportResult()
        for (uri in uris) {
            val bytes = withContext(Dispatchers.IO) { readAll(uri, MAX_KEY_FILE) }
            val r = repo.import(bytes)
            total = ImportResult(
                total.new + r.new, total.updated + r.updated, total.unchanged + r.unchanged,
                total.secret + r.secret, total.fingerprints + r.fingerprints,
            )
        }
        say(total.summary())
        if (total.fingerprints.size == 1) navigate(Routes.cert(total.fingerprints.first()))
    }

    fun generateKey(
        name: String,
        email: String,
        algorithm: KeyAlgorithm,
        expires: Date?,
        passphrase: String,
        onCreated: (String) -> Unit,
    ) = launchOp("Generating key pair…\nThis can take a while for RSA keys.") {
        val ring = withContext(Dispatchers.Default) {
            PgpOps.generate(name, email, algorithm, expires, passphrase)
        }
        val fpr = repo.store(ring)
        say("Key pair created. Consider backing up your secret key.")
        onCreated(fpr)
    }

    fun delete(fpr: String, onDone: () -> Unit) = launchOp("Deleting…") {
        repo.delete(fpr)
        passCache.remove(fpr)
        say("Certificate deleted")
        onDone()
    }

    fun armoredPublicKey(fpr: String): String? = repo.publicRing(fpr)?.let(PgpUtil::armor)

    fun exportToUri(fpr: String, secret: Boolean, uri: Uri) = launchOp("Exporting…") {
        val ring = (if (secret) repo.secretRing(fpr) else repo.publicRing(fpr))
            ?: error("Certificate not found")
        withContext(Dispatchers.IO) {
            resolver.openOutputStream(uri, "w")?.use { it.write(PgpUtil.armor(ring).toByteArray()) }
                ?: error("Can't write to the selected file")
        }
        say(if (secret) "Secret key exported. Keep that file safe!" else "Certificate exported")
    }

    fun changePassphrase(fpr: String, old: String, new: String) = launchOp("Changing passphrase…") {
        val ring = repo.secretRing(fpr) ?: error("Secret key not found")
        val protectedKey = PgpUtil.isProtected(ring)
        if (protectedKey && !PgpUtil.checkPassphrase(ring, old)) {
            say("The current passphrase is wrong.")
            return@launchOp
        }
        val updated = withContext(Dispatchers.Default) {
            PgpOps.changePassphrase(ring, if (protectedKey) old else "", new)
        }
        repo.store(updated)
        passCache.remove(fpr)
        say("Passphrase changed")
    }

    fun changeExpiration(fpr: String, expires: Date?) = launchOp("Updating expiration…") {
        val ring = repo.secretRing(fpr) ?: error("Secret key not found")
        val pass = unlock(fpr, "Unlock your key to change its expiration date.") ?: return@launchOp
        val updated = withContext(Dispatchers.Default) { PgpOps.setExpiration(ring, pass, expires) }
        repo.store(updated)
        say(if (expires == null) "The key no longer expires" else "Expiration set to ${date(expires)}")
    }

    // ================================================================ keyserver

    fun lookup(query: String) {
        viewModelScope.launch {
            _lookup.value = LookupState(searching = true)
            _lookup.value = try {
                val outcome = KeyServer.lookup(query)
                LookupState(searched = true, hits = outcome.hits, errors = outcome.errors)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                LookupState(searched = true, errors = listOf(PgpOps.friendlyError(e)))
            }
        }
    }

    fun importHit(hit: LookupHit) = launchOp("Importing…") {
        say(repo.import(hit.ring.encoded).summary())
    }

    fun refreshFromServer(fpr: String) = launchOp("Updating from keyserver…") {
        val outcome = KeyServer.lookup(fpr)
        val hit = outcome.hits.firstOrNull { it.info.fingerprint == fpr }
        if (hit == null) {
            say(outcome.errors.firstOrNull() ?: "Not found on the keyservers")
        } else {
            say(repo.import(hit.ring.encoded).summary())
        }
    }

    fun publishToServer(fpr: String) = launchOp("Publishing to keys.openpgp.org…") {
        val armored = armoredPublicKey(fpr) ?: error("Certificate not found")
        _publish.value = PublishState(fpr, KeyServer.publish(armored))
    }

    fun requestVerification(addresses: List<String>) = launchOp("Requesting verification e-mails…") {
        val state = _publish.value ?: return@launchOp
        val r = KeyServer.requestVerification(state.result.token, addresses)
        _publish.value = state.copy(result = r.copy(token = r.token.ifBlank { state.result.token }))
        say("Check your inbox and click the verification link.")
    }

    fun dismissPublish() {
        _publish.value = null
    }

    // =================================================================== notepad

    fun signEncryptText(request: EncryptRequest) = launchOp(
        if (request.encrypts) "Encrypting…" else "Signing…",
        onError = { notepadResult.value = OpResult.error("Sign / Encrypt failed", it) },
    ) {
        lastEncrypt = request.copy(password = null)
        val text = notepadText.value
        if (text.isEmpty()) {
            say("The notepad is empty")
            return@launchOp
        }
        val prepared = prepare(request) ?: return@launchOp
        val out = ByteArrayOutputStream()
        withContext(Dispatchers.Default) {
            PgpOps.encryptOrSign(
                input = text.toByteArray().inputStream(),
                output = out,
                recipients = prepared.recipients,
                password = request.password,
                signer = prepared.signer,
                armor = true,
                textMode = true,
                cleartext = !request.encrypts,
            )
        }
        notepadText.value = out.toString("UTF-8")
        notepadResult.value = OpResult(
            if (request.encrypts) "Encryption succeeded" else "Signing succeeded",
            prepared.summary,
        )
    }

    fun decryptVerifyText() = launchOp(
        "Decrypting…",
        onError = { notepadResult.value = OpResult.error("Decrypt / Verify failed", it) },
    ) {
        val text = notepadText.value.trim()
        if (text.isEmpty()) {
            say("The notepad is empty")
            return@launchOp
        }
        val bytes = text.toByteArray()
        when (PgpUtil.sniff(bytes)) {
            DataKind.KEYS -> {
                val r = repo.import(bytes)
                notepadResult.value = OpResult("Certificate import", listOf(ResultLine(LineKind.OK, r.summary())))
            }
            DataKind.DETACHED_SIGNATURE -> notepadResult.value = OpResult.error(
                "Detached signature",
                "This is a detached signature. Open it in Files and choose the signed file to verify it.",
            )
            DataKind.PLAIN -> notepadResult.value = OpResult.error(
                "Nothing to decrypt",
                "The notepad doesn't contain an OpenPGP message.",
            )
            DataKind.CLEARTEXT_SIGNED -> {
                val result = runDecrypt({ bytes.inputStream() }, NullOutputStream) ?: return@launchOp
                notepadResult.value = result
            }
            DataKind.MESSAGE -> {
                val out = ByteArrayOutputStream()
                val result = runDecrypt({ bytes.inputStream() }, out) ?: return@launchOp
                notepadText.value = out.toString("UTF-8")
                notepadResult.value = result
            }
        }
    }

    // ===================================================================== files

    fun pickFile(uri: Uri) {
        viewModelScope.launch {
            pickedFile.value = withContext(Dispatchers.IO) { describe(uri) }
            filesResult.value = null
        }
    }

    fun clearPickedFile() {
        pickedFile.value = null
        filesResult.value = null
    }

    fun signEncryptFile(request: EncryptRequest, output: Uri) = launchOp(
        if (request.encrypts) "Encrypting file…" else "Signing file…",
        onError = { filesResult.value = OpResult.error("Sign / Encrypt failed", it) },
    ) {
        lastEncrypt = request.copy(password = null)
        val input = pickedFile.value ?: return@launchOp
        val prepared = prepare(request)
        if (prepared == null) {
            deleteDocument(output)
            return@launchOp
        }
        try {
            withContext(Dispatchers.IO) {
                openIn(input.uri).use { ins ->
                    openOut(output).use { outs ->
                        PgpOps.encryptOrSign(
                            input = ins,
                            output = outs,
                            recipients = prepared.recipients,
                            password = request.password,
                            signer = prepared.signer,
                            armor = request.armor,
                            textMode = false,
                            fileName = input.name,
                        )
                    }
                }
            }
        } catch (e: Throwable) {
            deleteDocument(output)
            throw e
        }
        filesResult.value = OpResult(
            if (request.encrypts) "Encryption succeeded" else "Signing succeeded",
            prepared.summary + ResultLine(LineKind.INFO, "Saved as ${displayName(output) ?: "the selected file"}"),
        )
    }

    fun decryptVerifyFile(output: Uri) = launchOp(
        "Decrypting file…",
        onError = { filesResult.value = OpResult.error("Decrypt / Verify failed", it) },
    ) {
        val input = pickedFile.value ?: return@launchOp
        val result = try {
            withContext(Dispatchers.IO) {
                openOut(output).use { outs -> runDecrypt({ openIn(input.uri) }, outs) }
            }
        } catch (e: Throwable) {
            deleteDocument(output)
            throw e
        }
        if (result == null) {
            deleteDocument(output)
            return@launchOp
        }
        filesResult.value = result.copy(
            lines = result.lines + ResultLine(LineKind.INFO, "Saved as ${displayName(output) ?: "the selected file"}"),
        )
    }

    /** Verify the picked detached signature against [data]. */
    fun verifyDetached(data: Uri) = launchOp(
        "Verifying…",
        onError = { filesResult.value = OpResult.error("Verification failed", it) },
    ) {
        val sig = pickedFile.value ?: return@launchOp
        val r = withContext(Dispatchers.IO) {
            openIn(sig.uri).use { sigIn ->
                openIn(data).use { dataIn ->
                    PgpOps.verifyDetached(dataIn, sigIn, repo.allPublicRings())
                }
            }
        }
        filesResult.value = OpResult(
            "Verification of ${displayName(data) ?: "file"}",
            describeSignatures(r, detached = true),
        )
    }

    // ================================================================== intents

    fun handleIntent(intent: Intent?) {
        intent ?: return
        when (intent.action) {
            Intent.ACTION_SEND -> {
                val uri = IntentCompat.getParcelableExtra(intent, Intent.EXTRA_STREAM, Uri::class.java)
                val text = intent.getStringExtra(Intent.EXTRA_TEXT)
                when {
                    uri != null -> handleUri(uri)
                    !text.isNullOrBlank() -> handleText(text)
                }
            }
            Intent.ACTION_VIEW -> intent.data?.let(::handleUri)
        }
    }

    private fun handleText(text: String) {
        when (PgpUtil.sniff(text.toByteArray())) {
            DataKind.KEYS -> {
                navigate(Routes.CERTS)
                importText(text)
            }
            DataKind.MESSAGE, DataKind.CLEARTEXT_SIGNED -> {
                notepadText.value = text
                notepadResult.value = null
                navigate(Routes.NOTEPAD)
                decryptVerifyText()
            }
            else -> {
                notepadText.value = text
                notepadResult.value = null
                navigate(Routes.NOTEPAD)
            }
        }
    }

    private fun handleUri(uri: Uri) {
        viewModelScope.launch {
            val file = try {
                withContext(Dispatchers.IO) { describe(uri) }
            } catch (e: Exception) {
                say("Can't open that file: ${e.message}")
                return@launch
            }
            val smallText = (file.size ?: Long.MAX_VALUE) < MAX_NOTEPAD_FILE
            when {
                file.kind == DataKind.KEYS -> {
                    navigate(Routes.CERTS)
                    importUris(listOf(uri))
                }
                smallText && (file.kind == DataKind.MESSAGE || file.kind == DataKind.CLEARTEXT_SIGNED) &&
                    isArmored(uri) -> {
                    val text = withContext(Dispatchers.IO) { readAll(uri, MAX_NOTEPAD_FILE).toString(Charsets.UTF_8) }
                    handleText(text)
                }
                else -> {
                    pickedFile.value = file
                    filesResult.value = null
                    navigate(Routes.FILES)
                }
            }
        }
    }

    // ================================================================== helpers

    private class Prepared(
        val recipients: List<PGPPublicKeyRing>,
        val signer: UnlockedKey?,
        val summary: List<ResultLine>,
    )

    private suspend fun prepare(request: EncryptRequest): Prepared? {
        val fprs = buildList {
            addAll(request.recipients)
            if (request.encryptToSelf && request.myFingerprint != null) add(request.myFingerprint)
        }.distinct()
        val recipients = fprs.map { repo.publicRing(it) ?: error("Certificate $it not found") }

        val signer = if (request.sign) {
            val fpr = request.myFingerprint ?: error("Choose a certificate to sign with")
            val ring = repo.secretRing(fpr) ?: error("Secret key not available")
            val pass = unlock(fpr, "Unlock your secret key to sign.") ?: return null
            UnlockedKey(ring, pass)
        } else null

        val summary = buildList {
            if (fprs.isNotEmpty()) {
                val names = fprs.map { repo.cert(it)?.label ?: it }
                add(ResultLine(LineKind.OK, "Encrypted for: " + names.joinToString("; ")))
            }
            if (!request.password.isNullOrEmpty()) add(ResultLine(LineKind.OK, "Encrypted with a password"))
            if (signer != null) {
                add(ResultLine(LineKind.OK, "Signed as " + (repo.cert(request.myFingerprint!!)?.label ?: "")))
            }
            if (request.encrypts && fprs.isNotEmpty() && !(request.encryptToSelf && request.myFingerprint != null)) {
                add(ResultLine(LineKind.INFO, "Not encrypted for yourself, so you won't be able to decrypt it."))
            }
        }
        return Prepared(recipients, signer, summary)
    }

    /** Decrypt and/or verify. Returns null if the user cancelled a passphrase prompt. */
    private suspend fun runDecrypt(open: () -> InputStream, out: OutputStream): OpResult? {
        val scan = withContext(Dispatchers.IO) { open().use { PgpUtil.scanMessage(it) } }
        val lines = mutableListOf<ResultLine>()
        var keys: List<UnlockedKey> = emptyList()
        var password: String? = null

        if (scan.encrypted) {
            val mine = scan.recipientKeyIds.filter { it != 0L }
                .mapNotNull { repo.secretRingForKeyId(it) }
                .distinctBy { PgpUtil.fingerprint(it.publicKey) }
            val candidates = if (mine.isEmpty() && 0L in scan.recipientKeyIds) repo.allSecretRings() else mine
            when {
                candidates.isNotEmpty() -> {
                    // Prefer a key that can be used without prompting.
                    val ring = candidates.minByOrNull { ring ->
                        val fpr = PgpUtil.fingerprint(ring.publicKey)
                        if (!PgpUtil.isProtected(ring) || passCache.containsKey(fpr)) 0 else 1
                    }!!
                    val fpr = PgpUtil.fingerprint(ring.publicKey)
                    val pass = unlock(fpr, "Unlock your secret key to decrypt.") ?: return null
                    keys = listOf(UnlockedKey(ring, pass))
                    lines += ResultLine(LineKind.OK, "Decrypted with " + (repo.cert(fpr)?.label ?: fpr))
                }
                scan.passwordEncrypted -> {
                    password = askPassword("Message password", "This message is protected with a password.")
                        ?: return null
                    lines += ResultLine(LineKind.OK, "Decrypted with a password")
                }
                else -> {
                    val names = scan.recipientKeyIds.map { id ->
                        repo.certForKeyId(id)?.label ?: "0x" + PgpUtil.keyIdHex(id)
                    }
                    return OpResult(
                        "Decryption failed",
                        listOf(
                            ResultLine(LineKind.ERROR, "None of your secret keys can decrypt this message."),
                            ResultLine(LineKind.INFO, "It was encrypted for: " + names.joinToString("; ")),
                        ),
                    )
                }
            }
        } else {
            // Not encrypted (or unrecognised): offer any key usable without a prompt, just in case.
            keys = repo.allSecretRings()
                .mapNotNull { ring ->
                    val fpr = PgpUtil.fingerprint(ring.publicKey)
                    when {
                        !PgpUtil.isProtected(ring) -> UnlockedKey(ring, "")
                        passCache.containsKey(fpr) -> UnlockedKey(ring, passCache.getValue(fpr))
                        else -> null
                    }
                }
        }

        val result = withContext(Dispatchers.IO) {
            open().use { input -> PgpOps.decryptOrVerify(input, out, keys, repo.allPublicRings(), password) }
        }
        lines += describeSignatures(result, detached = false)
        return OpResult(if (scan.encrypted) "Decryption succeeded" else "Verification", lines)
    }

    private fun describeSignatures(r: VerifyResult, detached: Boolean): List<ResultLine> = buildList {
        for (sig in r.verified) {
            val cert = repo.certForKeyId(sig.keyID)
            val who = cert?.label ?: ("0x" + PgpUtil.keyIdHex(sig.keyID))
            val whenSigned = dateTime(sig.creationTime)
            add(
                when {
                    cert?.revoked == true -> ResultLine(
                        LineKind.WARN,
                        "Signature by $who ($whenSigned) is mathematically valid, but the certificate has been revoked.",
                    )
                    cert?.isExpired == true -> ResultLine(
                        LineKind.WARN,
                        "Valid signature by $who ($whenSigned), but the certificate has expired.",
                    )
                    else -> ResultLine(LineKind.OK, "Valid signature by $who ($whenSigned)")
                },
            )
        }
        if (r.rejectedCount > 0) {
            add(
                ResultLine(
                    if (r.verified.isEmpty()) LineKind.ERROR else LineKind.WARN,
                    "${r.rejectedCount} signature(s) could not be verified: the signature is bad or the " +
                        "signer's certificate is missing. Try “Lookup on server” to fetch it.",
                ),
            )
        }
        if (r.verified.isEmpty() && r.rejectedCount == 0) {
            add(
                if (detached) ResultLine(LineKind.ERROR, "No valid signature found.")
                else ResultLine(LineKind.INFO, "The message is not signed."),
            )
        }
    }

    private fun describe(uri: Uri): PickedFile {
        var name: String? = null
        var size: Long? = null
        resolver.query(uri, null, null, null, null)?.use { c ->
            if (c.moveToFirst()) {
                val n = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                val s = c.getColumnIndex(OpenableColumns.SIZE)
                if (n >= 0) name = c.getString(n)
                if (s >= 0 && !c.isNull(s)) size = c.getLong(s)
            }
        }
        val head = openIn(uri).use { input ->
            val buf = ByteArray(HEAD_SIZE)
            var read = 0
            while (read < buf.size) {
                val n = input.read(buf, read, buf.size - read)
                if (n < 0) break
                read += n
            }
            buf.copyOf(read)
        }
        return PickedFile(uri, name ?: uri.lastPathSegment ?: "file", size, PgpUtil.sniff(head))
    }

    private suspend fun isArmored(uri: Uri): Boolean = withContext(Dispatchers.IO) {
        openIn(uri).use { input ->
            val buf = ByteArray(4096)
            val n = input.read(buf).coerceAtLeast(0)
            String(buf, 0, n, Charsets.ISO_8859_1).contains("-----BEGIN PGP")
        }
    }

    private fun openIn(uri: Uri): InputStream =
        resolver.openInputStream(uri) ?: error("Can't open the file")

    private fun openOut(uri: Uri): OutputStream =
        resolver.openOutputStream(uri, "w") ?: error("Can't write to the selected file")

    private fun readAll(uri: Uri, limit: Long): ByteArray = openIn(uri).use { input ->
        val out = ByteArrayOutputStream()
        val buf = ByteArray(8192)
        var total = 0L
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            total += n
            if (total > limit) error("File is too large")
            out.write(buf, 0, n)
        }
        out.toByteArray()
    }

    private fun displayName(uri: Uri): String? = runCatching {
        resolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c ->
            if (c.moveToFirst()) c.getString(0) else null
        }
    }.getOrNull()

    private fun deleteDocument(uri: Uri) {
        runCatching { DocumentsContract.deleteDocument(resolver, uri) }
    }

    private object NullOutputStream : OutputStream() {
        override fun write(b: Int) = Unit
        override fun write(b: ByteArray, off: Int, len: Int) = Unit
    }

    companion object {
        private const val TAG = "Kleo"
        private const val HEAD_SIZE = 64 * 1024
        private const val MAX_KEY_FILE = 20L * 1024 * 1024
        private const val MAX_NOTEPAD_FILE = 256L * 1024

        fun date(d: Date): String = DateFormat.getDateInstance(DateFormat.MEDIUM).format(d)
        fun dateTime(d: Date): String = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT).format(d)
    }
}
