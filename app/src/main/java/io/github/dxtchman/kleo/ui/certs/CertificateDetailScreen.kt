package io.github.dxtchman.kleo.ui.certs

import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CloudSync
import androidx.compose.material.icons.filled.CloudUpload
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Event
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Password
import androidx.compose.material.icons.filled.Save
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.dxtchman.kleo.crypto.CertInfo
import io.github.dxtchman.kleo.crypto.KeyUsage
import io.github.dxtchman.kleo.crypto.PgpUtil
import io.github.dxtchman.kleo.crypto.SubkeyInfo
import io.github.dxtchman.kleo.ui.AppViewModel
import io.github.dxtchman.kleo.ui.common.Avatar
import io.github.dxtchman.kleo.ui.common.CheckRow
import io.github.dxtchman.kleo.ui.common.ConfirmDialog
import io.github.dxtchman.kleo.ui.common.PasswordField
import io.github.dxtchman.kleo.ui.common.SectionLabel
import io.github.dxtchman.kleo.ui.theme.LocalStatusColors
import java.util.Calendar
import java.util.Date

private enum class DetailDialog { NONE, DELETE, EXPORT_SECRET, PASSPHRASE, EXPIRY, PUBLISH }

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CertificateDetailScreen(vm: AppViewModel, fpr: String, onBack: () -> Unit) {
    val certs by vm.certs.collectAsStateWithLifecycle()
    val publish by vm.publish.collectAsStateWithLifecycle()
    val cert = certs.firstOrNull { it.fingerprint == fpr }
    val context = LocalContext.current
    val clipboard = LocalClipboardManager.current
    var menu by remember { mutableStateOf(false) }
    var dialog by remember { mutableStateOf(DetailDialog.NONE) }

    val exportPublic = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/pgp-keys")) { uri ->
        uri?.let { vm.exportToUri(fpr, secret = false, uri = it) }
    }
    val exportSecret = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/pgp-keys")) { uri ->
        uri?.let { vm.exportToUri(fpr, secret = true, uri = it) }
    }

    val baseName = cert?.let { (it.email ?: it.name).replace(Regex("[^A-Za-z0-9@._-]"), "_") + "_" + it.keyIdHex } ?: fpr

    fun share() {
        val armored = vm.armoredPublicKey(fpr) ?: return
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_SUBJECT, "OpenPGP certificate of ${cert?.label}")
            putExtra(Intent.EXTRA_TEXT, armored)
        }
        context.startActivity(Intent.createChooser(send, "Share certificate"))
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Certificate details") },
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") }
                },
                actions = {
                    if (cert != null) {
                        IconButton(onClick = ::share) { Icon(Icons.Filled.Share, contentDescription = "Share public key") }
                        IconButton(onClick = { menu = true }) { Icon(Icons.Filled.MoreVert, contentDescription = "More") }
                        DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                            MenuItem("Copy public key", Icons.Filled.ContentCopy) {
                                menu = false
                                vm.armoredPublicKey(fpr)?.let { clipboard.setText(AnnotatedString(it)) }
                            }
                            MenuItem("Export public key…", Icons.Filled.Save) {
                                menu = false
                                exportPublic.launch("$baseName.asc")
                            }
                            if (cert.isSecret) {
                                MenuItem("Back up secret key…", Icons.Filled.Key) {
                                    menu = false
                                    dialog = DetailDialog.EXPORT_SECRET
                                }
                                MenuItem("Change passphrase", Icons.Filled.Password) {
                                    menu = false
                                    dialog = DetailDialog.PASSPHRASE
                                }
                                MenuItem("Change expiration", Icons.Filled.Event) {
                                    menu = false
                                    dialog = DetailDialog.EXPIRY
                                }
                                MenuItem("Publish on keys.openpgp.org", Icons.Filled.CloudUpload) {
                                    menu = false
                                    vm.publishToServer(fpr)
                                    dialog = DetailDialog.PUBLISH
                                }
                            }
                            MenuItem("Update from keyserver", Icons.Filled.CloudSync) {
                                menu = false
                                vm.refreshFromServer(fpr)
                            }
                            HorizontalDivider()
                            MenuItem("Delete", Icons.Filled.Delete) {
                                menu = false
                                dialog = DetailDialog.DELETE
                            }
                        }
                    }
                },
            )
        },
    ) { padding ->
        if (cert == null) {
            Text("This certificate is no longer in your keyring.", modifier = Modifier.padding(padding).padding(24.dp))
            return@Scaffold
        }
        Column(
            modifier = Modifier
                .padding(padding)
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Header(cert)
            Spacer(Modifier.size(8.dp))
            FingerprintCard(cert.fingerprint) { clipboard.setText(AnnotatedString(cert.fingerprint)) }

            SectionLabel("Details")
            InfoRow("Type", if (cert.isSecret) "Your key pair (public + secret key)" else "Public certificate")
            InfoRow("Status", statusText(cert))
            InfoRow("Created", AppViewModel.date(cert.created))
            InfoRow("Expires", cert.expires?.let(AppViewModel::date) ?: "Never")
            InfoRow("Algorithm", cert.algorithm)
            InfoRow("Usage", KeyUsage.describe(cert.subkeys.filter { it.isUsable }.fold(0) { acc, k -> acc or k.flags }))
            InfoRow("Key ID", PgpUtil.formatFingerprint(cert.keyIdHex), mono = true)

            SectionLabel("User IDs")
            cert.userIds.forEachIndexed { index, uid ->
                Column(Modifier.padding(vertical = 6.dp)) {
                    Text(
                        uid.name.ifBlank { uid.email ?: uid.raw },
                        style = MaterialTheme.typography.bodyLarge,
                        fontWeight = if (index == 0) FontWeight.SemiBold else FontWeight.Normal,
                    )
                    val extra = listOfNotNull(uid.email?.takeIf { uid.name.isNotBlank() }, uid.comment?.let { "($it)" })
                    if (extra.isNotEmpty()) {
                        Text(extra.joinToString(" "), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }

            SectionLabel("Subkeys")
            cert.subkeys.forEach { SubkeyCard(it) }

            Spacer(Modifier.size(24.dp))
        }
    }

    when (dialog) {
        DetailDialog.NONE -> Unit
        DetailDialog.DELETE -> ConfirmDialog(
            title = "Delete certificate?",
            text = if (cert?.isSecret == true) {
                "This deletes your SECRET KEY for ${cert?.label}. Without a backup you will never be able to decrypt " +
                    "messages sent to this key again. This can't be undone."
            } else {
                "Remove ${cert?.label} from your keyring?"
            },
            confirmLabel = "Delete",
            destructive = true,
            onConfirm = { dialog = DetailDialog.NONE; vm.delete(fpr, onBack) },
            onDismiss = { dialog = DetailDialog.NONE },
        )
        DetailDialog.EXPORT_SECRET -> ConfirmDialog(
            title = "Back up secret key",
            text = "The backup contains your secret key, protected by your passphrase. Store it somewhere safe and " +
                "never share it — anyone with this file and your passphrase can read your messages and sign as you.",
            confirmLabel = "Choose location",
            onConfirm = { dialog = DetailDialog.NONE; exportSecret.launch("${baseName}_SECRET.asc") },
            onDismiss = { dialog = DetailDialog.NONE },
        )
        DetailDialog.PASSPHRASE -> ChangePassphraseDialog(
            needsOld = vm.isProtected(fpr),
            onDismiss = { dialog = DetailDialog.NONE },
            onConfirm = { old, new -> dialog = DetailDialog.NONE; vm.changePassphrase(fpr, old, new) },
        )
        DetailDialog.EXPIRY -> ExpiryDialog(
            onDismiss = { dialog = DetailDialog.NONE },
            onConfirm = { date -> dialog = DetailDialog.NONE; vm.changeExpiration(fpr, date) },
        )
        DetailDialog.PUBLISH -> publish?.takeIf { it.fingerprint == fpr }?.let { state ->
            PublishDialog(
                status = state.result.addressStatus,
                onVerify = { addresses -> vm.requestVerification(addresses) },
                onDismiss = { dialog = DetailDialog.NONE; vm.dismissPublish() },
            )
        }
    }
}

@Composable
private fun MenuItem(text: String, icon: androidx.compose.ui.graphics.vector.ImageVector, onClick: () -> Unit) {
    DropdownMenuItem(
        text = { Text(text) },
        leadingIcon = { Icon(icon, contentDescription = null) },
        onClick = onClick,
    )
}

private fun statusText(cert: CertInfo) = when {
    cert.revoked -> "Revoked"
    cert.isExpired -> "Expired"
    else -> "Valid"
}

@Composable
private fun Header(cert: CertInfo) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Avatar(cert.name, cert.isSecret, modifier = Modifier.size(56.dp))
        Spacer(Modifier.width(16.dp))
        Column(Modifier.weight(1f)) {
            Text(cert.name, style = MaterialTheme.typography.headlineSmall)
            cert.email?.takeIf { it != cert.name }?.let {
                Text(it, style = MaterialTheme.typography.bodyLarge, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        val status = LocalStatusColors.current
        when {
            cert.revoked -> StatusTag("Revoked", status.errorContainer, status.onError)
            cert.isExpired -> StatusTag("Expired", status.warnContainer, status.onWarn)
            else -> StatusTag("Valid", status.okContainer, status.onOk)
        }
    }
}

@Composable
private fun FingerprintCard(fingerprint: String, onCopy: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(start = 16.dp, top = 8.dp, bottom = 8.dp)) {
            Column(Modifier.weight(1f)) {
                Text("Fingerprint", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                SelectionContainer {
                    Text(
                        PgpUtil.formatFingerprint(fingerprint).replace("  ", "\n"),
                        fontFamily = FontFamily.Monospace,
                        style = MaterialTheme.typography.bodyLarge,
                    )
                }
            }
            IconButton(onClick = onCopy) { Icon(Icons.Filled.ContentCopy, contentDescription = "Copy fingerprint") }
        }
    }
}

@Composable
private fun InfoRow(label: String, value: String, mono: Boolean = false) {
    Row(Modifier.padding(vertical = 4.dp)) {
        Text(
            label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.width(110.dp),
        )
        Text(
            value,
            style = MaterialTheme.typography.bodyMedium,
            fontFamily = if (mono) FontFamily.Monospace else null,
        )
    }
}

@Composable
private fun SubkeyCard(key: SubkeyInfo) {
    Card(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Column(Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    PgpUtil.formatFingerprint(PgpUtil.keyIdHex(key.keyId)),
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.weight(1f),
                )
                if (key.isPrimary) Text("primary", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.primary)
            }
            Text(
                "${key.algorithm} · ${KeyUsage.describe(key.flags)}",
                style = MaterialTheme.typography.bodySmall,
            )
            Text(
                buildString {
                    append("Created ").append(AppViewModel.date(key.created))
                    append(" · ")
                    append(key.expires?.let { (if (key.isExpired) "Expired " else "Expires ") + AppViewModel.date(it) } ?: "No expiry")
                    if (key.revoked) append(" · Revoked")
                    if (key.hasSecret) append(" · Secret key available")
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun ChangePassphraseDialog(needsOld: Boolean, onDismiss: () -> Unit, onConfirm: (String, String) -> Unit) {
    var old by remember { mutableStateOf("") }
    var new by remember { mutableStateOf("") }
    var repeat by remember { mutableStateOf("") }
    val mismatch = repeat.isNotEmpty() && new != repeat
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Change passphrase") },
        text = {
            Column {
                if (needsOld) PasswordField(old, { old = it }, "Current passphrase")
                PasswordField(new, { new = it }, "New passphrase")
                PasswordField(
                    repeat, { repeat = it }, "Repeat new passphrase",
                    isError = mismatch,
                    supportingText = if (mismatch) "Passphrases don't match" else null,
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(old, new) },
                enabled = new.isNotEmpty() && new == repeat && (!needsOld || old.isNotEmpty()),
            ) { Text("Change") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun ExpiryDialog(onDismiss: () -> Unit, onConfirm: (Date?) -> Unit) {
    val options = listOf("Never" to 0, "1 year from now" to 1, "2 years from now" to 2, "3 years from now" to 3, "5 years from now" to 5)
    var choice by remember { mutableIntStateOf(2) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Change expiration") },
        text = {
            Column {
                Text(
                    "Expiration is a safety net: if you lose your key, it stops being used automatically. You can always extend it later.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Spacer(Modifier.size(8.dp))
                options.forEach { (label, years) ->
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        modifier = Modifier
                            .fillMaxWidth()
                            .selectable(selected = choice == years, role = Role.RadioButton) { choice = years },
                    ) {
                        RadioButton(selected = choice == years, onClick = null)
                        Spacer(Modifier.width(8.dp))
                        Text(label)
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = { onConfirm(yearsFromNow(choice)) }) { Text("Apply") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

fun yearsFromNow(years: Int): Date? = if (years <= 0) null else Calendar.getInstance().apply { add(Calendar.YEAR, years) }.time

@Composable
private fun PublishDialog(status: Map<String, String>, onVerify: (List<String>) -> Unit, onDismiss: () -> Unit) {
    var selected by remember(status) { mutableStateOf(status.filterValues { it == "unpublished" }.keys) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Published on keys.openpgp.org") },
        text = {
            Column {
                Text(
                    "Your certificate was uploaded. To make it findable by e-mail address, keys.openpgp.org sends a " +
                        "verification link to each address.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Spacer(Modifier.size(8.dp))
                status.forEach { (address, state) ->
                    val label = when (state) {
                        "published" -> "$address — published"
                        "pending" -> "$address — verification e-mail sent"
                        "revoked" -> "$address — revoked"
                        else -> address
                    }
                    CheckRow(label, address in selected, enabled = state == "unpublished") {
                        selected = if (it) selected + address else selected - address
                    }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = { onVerify(selected.toList()) }, enabled = selected.isNotEmpty()) { Text("Send verification") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Close") } },
    )
}
