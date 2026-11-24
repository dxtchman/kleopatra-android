package io.github.dxtchman.kleo.ui.notepad

import android.content.Intent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.dxtchman.kleo.ui.AppViewModel
import io.github.dxtchman.kleo.ui.common.ResultBanner
import io.github.dxtchman.kleo.ui.common.SignEncryptSheet

/** Kleopatra's Notepad: write or paste text, then sign/encrypt or decrypt/verify it in place. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NotepadScreen(vm: AppViewModel) {
    val text by vm.notepadText.collectAsStateWithLifecycle()
    val result by vm.notepadResult.collectAsStateWithLifecycle()
    val certs by vm.certs.collectAsStateWithLifecycle()
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    var sheet by remember { mutableStateOf(false) }

    Scaffold(
        contentWindowInsets = WindowInsets(0),
        topBar = {
            TopAppBar(
                title = { Text("Notepad") },
                actions = {
                    IconButton(onClick = {
                        clipboard.getText()?.text?.let { vm.notepadText.value = it; vm.notepadResult.value = null }
                    }) { Icon(Icons.Filled.ContentPaste, contentDescription = "Paste") }
                    IconButton(onClick = { clipboard.setText(AnnotatedString(text)) }, enabled = text.isNotEmpty()) {
                        Icon(Icons.Filled.ContentCopy, contentDescription = "Copy")
                    }
                    IconButton(
                        onClick = {
                            val send = Intent(Intent.ACTION_SEND).apply {
                                type = "text/plain"
                                putExtra(Intent.EXTRA_TEXT, text)
                            }
                            context.startActivity(Intent.createChooser(send, "Share"))
                        },
                        enabled = text.isNotEmpty(),
                    ) { Icon(Icons.Filled.Share, contentDescription = "Share") }
                    IconButton(
                        onClick = { vm.notepadText.value = ""; vm.notepadResult.value = null },
                        enabled = text.isNotEmpty() || result != null,
                    ) { Icon(Icons.Filled.DeleteSweep, contentDescription = "Clear") }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .fillMaxSize()
                .imePadding()
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            result?.let { ResultBanner(it, onDismiss = { vm.notepadResult.value = null }) }

            OutlinedTextField(
                value = text,
                onValueChange = { vm.notepadText.value = it },
                placeholder = {
                    Text("Write a message to encrypt or sign, or paste an encrypted / signed message to decrypt or verify it.")
                },
                textStyle = MaterialTheme.typography.bodyMedium.copy(fontFamily = FontFamily.Monospace),
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f),
            )

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                Button(onClick = { sheet = true }, enabled = text.isNotEmpty(), modifier = Modifier.weight(1f)) {
                    Icon(Icons.Filled.Lock, contentDescription = null)
                    Text("  Sign / Encrypt")
                }
                FilledTonalButton(onClick = { vm.decryptVerifyText() }, enabled = text.isNotEmpty(), modifier = Modifier.weight(1f)) {
                    Icon(Icons.Filled.LockOpen, contentDescription = null)
                    Text("  Decrypt / Verify")
                }
            }
        }
    }

    if (sheet) {
        SignEncryptSheet(
            certs = certs,
            initial = vm.lastEncrypt,
            forFiles = false,
            onDismiss = { sheet = false },
            onConfirm = { request ->
                sheet = false
                vm.signEncryptText(request)
            },
        )
    }
}
