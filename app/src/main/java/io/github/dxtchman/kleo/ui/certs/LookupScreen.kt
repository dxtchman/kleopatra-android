package io.github.dxtchman.kleo.ui.certs

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.dxtchman.kleo.crypto.LookupHit
import io.github.dxtchman.kleo.crypto.PgpUtil
import io.github.dxtchman.kleo.ui.AppViewModel
import io.github.dxtchman.kleo.ui.common.Avatar

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LookupScreen(vm: AppViewModel, onBack: () -> Unit, onOpen: (String) -> Unit) {
    val state by vm.lookupState.collectAsStateWithLifecycle()
    val certs by vm.certs.collectAsStateWithLifecycle()
    var query by rememberSaveable { mutableStateOf("") }
    val focus = LocalFocusManager.current
    val search: () -> Unit = {
        focus.clearFocus()
        if (query.isNotBlank()) vm.lookup(query)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Lookup on server") },
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") }
                },
            )
        },
    ) { padding ->
        Column(
            Modifier
                .padding(padding)
                .fillMaxSize()
                .imePadding(),
        ) {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                placeholder = { Text("E-mail, fingerprint or key ID") },
                singleLine = true,
                leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email, imeAction = ImeAction.Search),
                keyboardActions = KeyboardActions(onSearch = { search() }),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp),
            )
            Text(
                "Searches the Web Key Directory of the e-mail domain, keys.openpgp.org and keyserver.ubuntu.com.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(horizontal = 16.dp),
            )
            if (state.searching) {
                LinearProgressIndicator(Modifier.fillMaxWidth().padding(16.dp))
            }

            LazyColumn(contentPadding = PaddingValues(16.dp)) {
                if (state.searched && state.hits.isEmpty()) {
                    item {
                        Text(
                            "No certificates found.",
                            style = MaterialTheme.typography.bodyLarge,
                            modifier = Modifier.padding(vertical = 8.dp),
                        )
                    }
                }
                items(state.errors) { error ->
                    Text(
                        error,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                        modifier = Modifier.padding(vertical = 2.dp),
                    )
                }
                items(state.hits, key = { it.info.fingerprint }) { hit ->
                    val local = certs.firstOrNull { it.fingerprint == hit.info.fingerprint }
                    HitCard(
                        hit = hit,
                        inKeyring = local != null,
                        onImport = { vm.importHit(hit) },
                        onOpen = { onOpen(hit.info.fingerprint) },
                    )
                }
            }
        }
    }
}

@Composable
private fun HitCard(hit: LookupHit, inKeyring: Boolean, onImport: () -> Unit, onOpen: () -> Unit) {
    val info = hit.info
    Card(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
        Column(Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Avatar(info.name, secret = false)
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Text(info.name, style = MaterialTheme.typography.titleMedium)
                    info.userIds.mapNotNull { it.email }.distinct().forEach {
                        Text(it, style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }
            Spacer(Modifier.size(8.dp))
            Text(
                PgpUtil.formatFingerprint(info.fingerprint),
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.bodySmall,
            )
            Text(
                buildString {
                    append(info.algorithm)
                    append(" · created ").append(AppViewModel.date(info.created))
                    info.expires?.let { append(if (info.isExpired) " · expired " else " · expires ").append(AppViewModel.date(it)) }
                    if (info.revoked) append(" · REVOKED")
                    append(" · via ").append(hit.source)
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.size(8.dp))
            Row {
                Button(onClick = onImport) { Text(if (inKeyring) "Update" else "Import") }
                if (inKeyring) {
                    Spacer(Modifier.width(8.dp))
                    OutlinedButton(onClick = onOpen) { Text("Open") }
                }
            }
        }
    }
}
