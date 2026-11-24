package io.github.dxtchman.kleo.ui.files

import android.text.format.Formatter
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.FileOpen
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.LockOpen
import androidx.compose.material.icons.filled.Verified
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.dxtchman.kleo.crypto.DataKind
import io.github.dxtchman.kleo.ui.AppViewModel
import io.github.dxtchman.kleo.ui.common.EmptyState
import io.github.dxtchman.kleo.ui.common.ResultBanner
import io.github.dxtchman.kleo.ui.common.SignEncryptSheet

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FilesScreen(vm: AppViewModel) {
    val file by vm.pickedFile.collectAsStateWithLifecycle()
    val result by vm.filesResult.collectAsStateWithLifecycle()
    val certs by vm.certs.collectAsStateWithLifecycle()
    val context = LocalContext.current
    var sheet by remember { mutableStateOf(false) }

    val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let(vm::pickFile)
    }
    val saveEncrypted = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val request = vm.pendingFileRequest
        vm.pendingFileRequest = null
        if (uri != null && request != null) vm.signEncryptFile(request, uri)
    }
    val saveDecrypted = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        uri?.let(vm::decryptVerifyFile)
    }
    val pickSignedData = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let(vm::verifyDetached)
    }

    Scaffold(
        contentWindowInsets = WindowInsets(0),
        topBar = { TopAppBar(title = { Text("Files") }) },
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            result?.let { ResultBanner(it, onDismiss = { vm.filesResult.value = null }) }

            val f = file
            if (f == null) {
                EmptyState(
                    icon = Icons.Filled.FileOpen,
                    title = "Encrypt or decrypt a file",
                    text = "Choose a file to sign, encrypt, decrypt or verify. You can also share files to Kleo " +
                        "from any app, or open .gpg / .asc / .sig files with it.",
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Button(onClick = { pick.launch(arrayOf("*/*")) }, modifier = Modifier.fillMaxWidth()) {
                        Text("Choose file")
                    }
                }
            } else {
                Card(Modifier.fillMaxWidth()) {
                    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(start = 16.dp, top = 8.dp, bottom = 8.dp)) {
                        Icon(Icons.Filled.Description, contentDescription = null)
                        Spacer(Modifier.width(12.dp))
                        Column(Modifier.weight(1f)) {
                            Text(f.name, style = MaterialTheme.typography.titleMedium, maxLines = 2, overflow = TextOverflow.Ellipsis)
                            Text(
                                listOfNotNull(
                                    f.size?.let { Formatter.formatShortFileSize(context, it) },
                                    when (f.kind) {
                                        DataKind.MESSAGE -> "OpenPGP message"
                                        DataKind.CLEARTEXT_SIGNED -> "Signed text"
                                        DataKind.DETACHED_SIGNATURE -> "Detached signature"
                                        DataKind.KEYS -> "Certificates"
                                        DataKind.PLAIN -> null
                                    },
                                ).joinToString(" · "),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        IconButton(onClick = vm::clearPickedFile) { Icon(Icons.Filled.Close, contentDescription = "Clear") }
                    }
                }

                val looksEncrypted = f.kind == DataKind.MESSAGE || f.kind == DataKind.CLEARTEXT_SIGNED
                when (f.kind) {
                    DataKind.DETACHED_SIGNATURE -> {
                        Button(onClick = { pickSignedData.launch(arrayOf("*/*")) }, modifier = Modifier.fillMaxWidth()) {
                            Icon(Icons.Filled.Verified, contentDescription = null)
                            Text("  Verify — choose the signed file")
                        }
                    }
                    DataKind.KEYS -> {
                        Button(onClick = { vm.importUris(listOf(f.uri)) }, modifier = Modifier.fillMaxWidth()) {
                            Text("Import certificates")
                        }
                    }
                    else -> {
                        val decryptButton: @Composable () -> Unit = {
                            ActionButton(
                                primary = looksEncrypted,
                                text = "Decrypt / Verify",
                                icon = { Icon(Icons.Filled.LockOpen, contentDescription = null) },
                            ) { saveDecrypted.launch(decryptedName(f.name)) }
                        }
                        val encryptButton: @Composable () -> Unit = {
                            ActionButton(
                                primary = !looksEncrypted,
                                text = "Sign / Encrypt",
                                icon = { Icon(Icons.Filled.Lock, contentDescription = null) },
                            ) { sheet = true }
                        }
                        if (looksEncrypted) {
                            decryptButton()
                            encryptButton()
                        } else {
                            encryptButton()
                            decryptButton()
                        }
                    }
                }
                OutlinedButton(onClick = { pick.launch(arrayOf("*/*")) }, modifier = Modifier.fillMaxWidth()) {
                    Text("Choose a different file")
                }
            }
        }
    }

    val current = file
    if (sheet && current != null) {
        SignEncryptSheet(
            certs = certs,
            initial = vm.lastEncrypt,
            forFiles = true,
            onDismiss = { sheet = false },
            onConfirm = { request ->
                sheet = false
                vm.pendingFileRequest = request
                val ext = if (request.armor) ".asc" else ".gpg"
                saveEncrypted.launch(current.name + ext)
            },
        )
    }
}

@Composable
private fun ActionButton(primary: Boolean, text: String, icon: @Composable () -> Unit, onClick: () -> Unit) {
    if (primary) {
        Button(onClick = onClick, modifier = Modifier.fillMaxWidth()) {
            icon()
            Text("  $text")
        }
    } else {
        FilledTonalButton(onClick = onClick, modifier = Modifier.fillMaxWidth()) {
            icon()
            Text("  $text")
        }
    }
}

private fun decryptedName(name: String): String {
    val lower = name.lowercase()
    return listOf(".gpg", ".pgp", ".asc", ".sig").firstOrNull { lower.endsWith(it) }
        ?.let { name.dropLast(it.length) }
        ?.ifBlank { null }
        ?: "$name.decrypted"
}
