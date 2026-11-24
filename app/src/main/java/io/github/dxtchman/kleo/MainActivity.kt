package io.github.dxtchman.kleo

import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import io.github.dxtchman.kleo.ui.AppViewModel
import io.github.dxtchman.kleo.ui.KleoRoot
import io.github.dxtchman.kleo.ui.theme.KleoTheme

class MainActivity : ComponentActivity() {

    private val vm: AppViewModel by viewModels()

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        // Keep decrypted text and passphrases out of screenshots and the recents screen.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)

        if (savedInstanceState == null) vm.handleIntent(intent)

        setContent {
            KleoTheme {
                KleoRoot(vm)
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        vm.handleIntent(intent)
    }
}
