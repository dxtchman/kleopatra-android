package io.github.dxtchman.kleo.ui.certs

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.FileOpen
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.TravelExplore
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.dxtchman.kleo.crypto.CertInfo
import io.github.dxtchman.kleo.crypto.PgpUtil
import io.github.dxtchman.kleo.ui.AppViewModel
import io.github.dxtchman.kleo.ui.common.Avatar
import io.github.dxtchman.kleo.ui.common.EmptyState
import io.github.dxtchman.kleo.ui.theme.LocalStatusColors

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CertificatesScreen(
    vm: AppViewModel,
    onOpen: (String) -> Unit,
    onNewKey: () -> Unit,
    onLookup: () -> Unit,
) {
    val certs by vm.certs.collectAsStateWithLifecycle()
    val loaded by vm.loaded.collectAsStateWithLifecycle()
    var query by rememberSaveable { mutableStateOf("") }
    var filter by rememberSaveable { mutableIntStateOf(0) } // 0 = all, 1 = mine, 2 = others
    var menu by remember { mutableStateOf(false) }
    var pasting by remember { mutableStateOf(false) }

    val importLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        if (uris.isNotEmpty()) vm.importUris(uris)
    }
    val openImport = { importLauncher.launch(arrayOf("*/*")) }

    val shown = certs.filter {
        it.matches(query) && when (filter) {
            1 -> it.isSecret
            2 -> !it.isSecret
            else -> true
        }
    }

    Scaffold(
        contentWindowInsets = WindowInsets(0),
        topBar = {
            TopAppBar(
                title = { Text("Certificates") },
                actions = {
                    IconButton(onClick = openImport) { Icon(Icons.Filled.FileOpen, contentDescription = "Import") }
                    IconButton(onClick = onLookup) { Icon(Icons.Filled.TravelExplore, contentDescription = "Lookup on server") }
                    Box {
                        IconButton(onClick = { menu = true }) { Icon(Icons.Filled.MoreVert, contentDescription = "More") }
                        DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                            DropdownMenuItem(
                                text = { Text("Import from clipboard") },
                                leadingIcon = { Icon(Icons.Filled.ContentPaste, contentDescription = null) },
                                onClick = { menu = false; pasting = true },
                            )
                            DropdownMenuItem(
                                text = { Text("New key pair") },
                                leadingIcon = { Icon(Icons.Filled.Add, contentDescription = null) },
                                onClick = { menu = false; onNewKey() },
                            )
                            DropdownMenuItem(
                                text = { Text("Forget cached passphrases") },
                                leadingIcon = { Icon(Icons.Filled.Key, contentDescription = null) },
                                onClick = { menu = false; vm.forgetPassphrases() },
                            )
                        }
                    }
                },
            )
        },
        floatingActionButton = {
            if (certs.isNotEmpty()) {
                ExtendedFloatingActionButton(
                    onClick = onNewKey,
                    icon = { Icon(Icons.Filled.Add, contentDescription = null) },
                    text = { Text("New key pair") },
                )
            }
        },
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {
            if (loaded && certs.isEmpty()) {
                Box(Modifier.fillMaxSize().verticalScroll(rememberScrollState()), contentAlignment = Alignment.Center) {
                    EmptyState(
                        icon = Icons.Filled.Key,
                        title = "Welcome to Kleo",
                        text = "Manage your OpenPGP certificates, then encrypt, decrypt, sign and verify text and files. " +
                            "Start by creating your own key pair, or import certificates you already have.",
                    ) {
                        Button(onClick = onNewKey, modifier = Modifier.fillMaxWidth()) { Text("Create a key pair") }
                        OutlinedButton(onClick = openImport, modifier = Modifier.fillMaxWidth()) { Text("Import from file") }
                        OutlinedButton(onClick = { pasting = true }, modifier = Modifier.fillMaxWidth()) { Text("Import from clipboard") }
                        OutlinedButton(onClick = onLookup, modifier = Modifier.fillMaxWidth()) { Text("Lookup on server") }
                    }
                }
            } else {
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it },
                    leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                    trailingIcon = {
                        if (query.isNotEmpty()) {
                            IconButton(onClick = { query = "" }) { Icon(Icons.Filled.Close, contentDescription = "Clear") }
                        }
                    },
                    placeholder = { Text("Search name, e-mail, fingerprint") },
                    singleLine = true,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 4.dp),
                )
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    modifier = Modifier.padding(horizontal = 16.dp),
                ) {
                    listOf("All", "My certificates", "Others").forEachIndexed { index, label ->
                        FilterChip(selected = filter == index, onClick = { filter = index }, label = { Text(label) })
                    }
                }

                LazyColumn(
                    contentPadding = PaddingValues(bottom = 96.dp),
                    modifier = Modifier.fillMaxSize(),
                ) {
                    items(shown, key = { it.fingerprint }) { cert ->
                        CertRow(cert, onClick = { onOpen(cert.fingerprint) })
                    }
                    if (shown.isEmpty() && certs.isNotEmpty()) {
                        item {
                            Text(
                                "No certificates match.",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.padding(24.dp),
                            )
                        }
                    }
                }
            }
        }
    }

    if (pasting) {
        PasteKeyDialog(
            onDismiss = { pasting = false },
            onImport = { text -> pasting = false; vm.importText(text) },
        )
    }
}

@Composable
fun CertRow(cert: CertInfo, onClick: () -> Unit) {
    val status = LocalStatusColors.current
    ListItem(
        modifier = Modifier.clickable(onClick = onClick),
        leadingContent = { Avatar(cert.name, cert.isSecret) },
        headlineContent = { Text(cert.name, maxLines = 1, overflow = TextOverflow.Ellipsis) },
        supportingContent = {
            Column {
                cert.email?.takeIf { it != cert.name }?.let {
                    Text(it, maxLines = 1, overflow = TextOverflow.Ellipsis)
                }
                Text(
                    PgpUtil.formatFingerprint(cert.keyIdHex),
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        },
        trailingContent = {
            when {
                cert.revoked -> StatusTag("Revoked", status.errorContainer, status.onError)
                cert.isExpired -> StatusTag("Expired", status.warnContainer, status.onWarn)
                cert.isSecret -> StatusTag("Mine", MaterialTheme.colorScheme.primaryContainer, MaterialTheme.colorScheme.onPrimaryContainer)
            }
        },
    )
}

@Composable
fun StatusTag(text: String, bg: androidx.compose.ui.graphics.Color, fg: androidx.compose.ui.graphics.Color) {
    androidx.compose.material3.Surface(color = bg, contentColor = fg, shape = MaterialTheme.shapes.small) {
        Text(text, style = MaterialTheme.typography.labelSmall, modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp))
    }
}

@Composable
private fun PasteKeyDialog(onDismiss: () -> Unit, onImport: (String) -> Unit) {
    val clipboard = LocalClipboardManager.current
    var text by remember {
        mutableStateOf(clipboard.getText()?.text?.takeIf { it.contains("-----BEGIN PGP") }.orEmpty())
    }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Import from clipboard") },
        text = {
            OutlinedTextField(
                value = text,
                onValueChange = { text = it },
                placeholder = { Text("-----BEGIN PGP PUBLIC KEY BLOCK-----") },
                textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 160.dp, max = 320.dp),
            )
        },
        confirmButton = { TextButton(onClick = { onImport(text) }, enabled = text.isNotBlank()) { Text("Import") } },
        dismissButton = {
            Row {
                TextButton(onClick = { text = clipboard.getText()?.text.orEmpty() }) { Text("Paste") }
                TextButton(onClick = onDismiss) { Text("Cancel") }
            }
        },
    )
}
