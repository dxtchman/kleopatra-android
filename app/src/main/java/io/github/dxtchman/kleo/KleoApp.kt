package io.github.dxtchman.kleo

import android.app.Application
import io.github.dxtchman.kleo.crypto.KeyRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

class KleoApp : Application() {

    val appScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    lateinit var keys: KeyRepository
        private set

    override fun onCreate() {
        super.onCreate()
        // Android ships a stripped-down "BC" provider. Replace it with the full one so
        // modern algorithms (X25519, Ed25519, AEAD, ...) are available.
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        Security.insertProviderAt(BouncyCastleProvider(), 1)

        keys = KeyRepository(this)
        appScope.launch { keys.load() }
    }
}
