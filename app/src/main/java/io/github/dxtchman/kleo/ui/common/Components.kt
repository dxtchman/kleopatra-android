package io.github.dxtchman.kleo.ui.common

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDropDown
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Error
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.PersonAdd
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedCard
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import io.github.dxtchman.kleo.crypto.CertInfo
import io.github.dxtchman.kleo.crypto.PgpUtil
import io.github.dxtchman.kleo.ui.EncryptRequest
import io.github.dxtchman.kleo.ui.LineKind
import io.github.dxtchman.kleo.ui.OpResult
import io.github.dxtchman.kleo.ui.PassphraseRequest
import io.github.dxtchman.kleo.ui.theme.LocalStatusColors
import kotlinx.coroutines.launch

// ---------------------------------------------------------------- basics

@Composable
fun PasswordField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    isError: Boolean = false,
    supportingText: String? = null,
    imeAction: ImeAction = ImeAction.Next,
    onDone: (() -> Unit)? = null,
) {
    var visible by remember { mutableStateOf(false) }
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        singleLine = true,
        isError = isError,
        supportingText = supportingText?.let { { Text(it) } },
        visualTransformation = if (visible) VisualTransformation.None else PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = imeAction),
        keyboardActions = KeyboardActions(onDone = { onDone?.invoke() }),
        trailingIcon = {
            IconButton(onClick = { visible = !visible }) {
                Icon(
                    if (visible) Icons.Filled.VisibilityOff else Icons.Filled.Visibility,
                    contentDescription = if (visible) "Hide" else "Show",
                )
            }
        },
        modifier = modifier.fillMaxWidth(),
    )
}

@Composable
fun CheckRow(text: String, checked: Boolean, enabled: Boolean = true, onChange: (Boolean) -> Unit) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .toggleable(value = checked, enabled = enabled, role = Role.Checkbox, onValueChange = onChange)
            .padding(vertical = 4.dp),
    ) {
        Checkbox(checked = checked, onCheckedChange = null, enabled = enabled)
        Spacer(Modifier.width(12.dp))
        Text(
            text,
            style = MaterialTheme.typography.bodyLarge,
            color = if (enabled) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.38f),
        )
    }
}

@Composable
fun SectionLabel(text: String, modifier: Modifier = Modifier) {
    Text(
        text,
        style = MaterialTheme.typography.labelLarge,
        color = MaterialTheme.colorScheme.primary,
        modifier = modifier.padding(top = 16.dp, bottom = 4.dp),
    )
}

@Composable
fun Avatar(name: String, secret: Boolean, modifier: Modifier = Modifier) {
    val bg = if (secret) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.secondaryContainer
    val fg = if (secret) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSecondaryContainer
    Box(
        contentAlignment = Alignment.Center,
        modifier = modifier
            .size(40.dp)
            .background(bg, CircleShape),
    ) {
        if (secret) {
            Icon(Icons.Filled.Key, contentDescription = "Your key pair", tint = fg, modifier = Modifier.size(22.dp))
        } else {
            Text(
                name.trim().firstOrNull()?.uppercase() ?: "?",
                color = fg,
                style = MaterialTheme.typography.titleMedium,
            )
        }
    }
}

@Composable
fun MonoText(text: String, modifier: Modifier = Modifier) {
    Text(
        text,
        fontFamily = FontFamily.Monospace,
        style = MaterialTheme.typography.bodyMedium,
        modifier = modifier,
    )
}

@Composable
fun ConfirmDialog(
    title: String,
    text: String,
    confirmLabel: String,
    destructive: Boolean = false,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(title) },
        text = { Text(text) },
        confirmButton = {
            TextButton(
                onClick = onConfirm,
                colors = if (destructive) ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error)
                else ButtonDefaults.textButtonColors(),
            ) { Text(confirmLabel) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
fun BusyDialog(label: String) {
    Dialog(
        onDismissRequest = {},
        properties = DialogProperties(dismissOnBackPress = false, dismissOnClickOutside = false),
    ) {
        Surface(shape = MaterialTheme.shapes.large, tonalElevation = 6.dp) {
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(24.dp)) {
                CircularProgressIndicator(modifier = Modifier.size(32.dp))
                Spacer(Modifier.width(20.dp))
                Text(label, style = MaterialTheme.typography.bodyLarge)
            }
        }
    }
}

// --------------------------------------------------------------- results

private fun iconFor(kind: LineKind): ImageVector = when (kind) {
    LineKind.OK -> Icons.Filled.CheckCircle
    LineKind.WARN -> Icons.Filled.Warning
    LineKind.ERROR -> Icons.Filled.Error
    LineKind.INFO -> Icons.Filled.Info
}

/** Kleopatra-style coloured result banner. */
@Composable
fun ResultBanner(result: OpResult, onDismiss: () -> Unit, modifier: Modifier = Modifier) {
    val status = LocalStatusColors.current
    val (bg, fg) = when (result.kind) {
        LineKind.OK -> status.okContainer to status.onOk
        LineKind.WARN -> status.warnContainer to status.onWarn
        LineKind.ERROR -> status.errorContainer to status.onError
        LineKind.INFO -> status.infoContainer to status.onInfo
    }
    Card(
        colors = CardDefaults.cardColors(containerColor = bg, contentColor = fg),
        modifier = modifier.fillMaxWidth(),
    ) {
        Row(modifier = Modifier.padding(start = 16.dp, top = 12.dp, bottom = 12.dp, end = 4.dp)) {
            Column(Modifier.weight(1f)) {
                Text(result.title, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                result.lines.forEach { line ->
                    Row(modifier = Modifier.padding(top = 6.dp)) {
                        Icon(iconFor(line.kind), contentDescription = null, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(8.dp))
                        Text(line.text, style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }
            IconButton(onClick = onDismiss) { Icon(Icons.Filled.Close, contentDescription = "Dismiss") }
        }
    }
}

// ----------------------------------------------------------- passphrases

@Composable
fun PassphraseDialog(request: PassphraseRequest, check: suspend (String, String) -> Boolean) {
    var passphrase by remember(request) { mutableStateOf("") }
    var rememberIt by remember(request) { mutableStateOf(true) }
    var error by remember(request) { mutableStateOf<String?>(null) }
    var checking by remember(request) { mutableStateOf(false) }
    val scope = rememberCoroutineScope()
    val focus = remember { FocusRequester() }

    val submit: () -> Unit = submit@{
        if (checking) return@submit
        val fpr = request.fingerprint
        if (fpr == null) {
            request.submit(passphrase, false)
        } else {
            checking = true
            scope.launch {
                val ok = check(fpr, passphrase)
                checking = false
                if (ok) {
                    request.submit(passphrase, rememberIt)
                } else {
                    error = "Wrong passphrase. Try again."
                }
            }
        }
    }

    LaunchedEffect(request) { runCatching { focus.requestFocus() } }

    AlertDialog(
        onDismissRequest = { request.cancel() },
        icon = { Icon(Icons.Filled.Key, contentDescription = null) },
        title = { Text(request.title) },
        text = {
            Column {
                Text(request.message, style = MaterialTheme.typography.bodyMedium)
                Spacer(Modifier.size(16.dp))
                PasswordField(
                    value = passphrase,
                    onValueChange = { passphrase = it; error = null },
                    label = "Passphrase",
                    isError = error != null,
                    supportingText = error,
                    imeAction = ImeAction.Done,
                    onDone = submit,
                    modifier = Modifier.focusRequester(focus),
                )
                if (request.fingerprint != null) {
                    CheckRow("Remember until the app is closed", rememberIt) { rememberIt = it }
                }
            }
        },
        confirmButton = {
            TextButton(onClick = submit, enabled = !checking) {
                if (checking) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp) else Text("OK")
            }
        },
        dismissButton = { TextButton(onClick = { request.cancel() }) { Text("Cancel") } },
    )
}

// ------------------------------------------------------- choosing certs

@Composable
fun CertDropdown(certs: List<CertInfo>, selected: String?, onSelect: (String) -> Unit) {
    var open by remember { mutableStateOf(false) }
    val current = certs.firstOrNull { it.fingerprint == selected }
    Box {
        OutlinedCard(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { open = true },
        ) {
            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(12.dp)) {
                Column(Modifier.weight(1f)) {
                    Text(current?.name ?: "Choose…", style = MaterialTheme.typography.bodyLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    current?.let {
                        Text(
                            listOfNotNull(it.email, PgpUtil.formatFingerprint(it.keyIdHex)).joinToString(" · "),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                        )
                    }
                }
                Icon(Icons.Filled.ArrowDropDown, contentDescription = null)
            }
        }
        DropdownMenu(expanded = open, onDismissRequest = { open = false }) {
            certs.forEach { cert ->
                DropdownMenuItem(
                    text = {
                        Column {
                            Text(cert.name)
                            Text(
                                listOfNotNull(cert.email, PgpUtil.formatFingerprint(cert.keyIdHex)).joinToString(" · "),
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                    },
                    onClick = { onSelect(cert.fingerprint); open = false },
                )
            }
        }
    }
}

@Composable
fun RecipientPicker(
    candidates: List<CertInfo>,
    selected: List<String>,
    onDismiss: () -> Unit,
    onDone: (List<String>) -> Unit,
) {
    var query by remember { mutableStateOf("") }
    var chosen by remember { mutableStateOf(selected.toSet()) }
    val shown = candidates.filter { it.matches(query) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Choose recipients") },
        text = {
            Column {
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it },
                    leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                    placeholder = { Text("Search name, e-mail, key ID") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Spacer(Modifier.size(8.dp))
                if (shown.isEmpty()) {
                    Text(
                        if (candidates.isEmpty()) "No certificates you can encrypt to. Import or look up your contacts' certificates first."
                        else "No matches.",
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.padding(vertical = 16.dp),
                    )
                }
                LazyColumn(modifier = Modifier.heightIn(max = 380.dp)) {
                    items(shown, key = { it.fingerprint }) { cert ->
                        val isChecked = cert.fingerprint in chosen
                        ListItem(
                            headlineContent = { Text(cert.name, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                            supportingContent = {
                                Text(
                                    listOfNotNull(cert.email, PgpUtil.formatFingerprint(cert.keyIdHex)).joinToString("\n"),
                                    style = MaterialTheme.typography.bodySmall,
                                )
                            },
                            leadingContent = { Checkbox(checked = isChecked, onCheckedChange = null) },
                            modifier = Modifier.toggleable(value = isChecked, role = Role.Checkbox) {
                                chosen = if (it) chosen + cert.fingerprint else chosen - cert.fingerprint
                            },
                        )
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = { onDone(chosen.toList()) }) { Text("Done") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

/**
 * The Sign / Encrypt options sheet shared by the notepad and the file screen,
 * modelled on Kleopatra's sign/encrypt dialog.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SignEncryptSheet(
    certs: List<CertInfo>,
    initial: EncryptRequest?,
    forFiles: Boolean,
    onDismiss: () -> Unit,
    onConfirm: (EncryptRequest) -> Unit,
) {
    val mine = certs.filter { it.isSecret && it.isValid }
    var myFpr by remember {
        mutableStateOf(
            initial?.myFingerprint?.takeIf { f -> mine.any { it.fingerprint == f } } ?: mine.firstOrNull()?.fingerprint,
        )
    }
    val me = mine.firstOrNull { it.fingerprint == myFpr }
    var sign by remember { mutableStateOf(initial?.sign ?: true) }
    var toSelf by remember { mutableStateOf(initial?.encryptToSelf ?: true) }
    var recipients by remember {
        mutableStateOf(initial?.recipients.orEmpty().filter { f -> certs.any { it.fingerprint == f && it.canEncrypt } })
    }
    var usePassword by remember { mutableStateOf(false) }
    var password by remember { mutableStateOf("") }
    var password2 by remember { mutableStateOf("") }
    var armor by remember { mutableStateOf(if (forFiles) initial?.armor ?: false else true) }
    var picking by remember { mutableStateOf(false) }

    val canSign = me?.canSign == true
    val canSelf = me?.canEncrypt == true
    val request = EncryptRequest(
        myFingerprint = myFpr,
        sign = sign && canSign,
        encryptToSelf = toSelf && canSelf,
        recipients = recipients,
        password = if (usePassword) password else null,
        armor = armor,
    )
    val passwordOk = !usePassword || (password.isNotEmpty() && password == password2)
    val valid = (request.encrypts || request.sign) && passwordOk

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
    ) {
        Column(
            modifier = Modifier
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp)
                .padding(bottom = 32.dp),
        ) {
            Text("Sign / Encrypt", style = MaterialTheme.typography.titleLarge)

            SectionLabel("Your certificate")
            if (mine.isEmpty()) {
                Text(
                    "You don't have a key pair yet. Create one on the Certificates tab to sign or to encrypt for yourself.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            } else {
                CertDropdown(mine, myFpr) { myFpr = it }
            }
            CheckRow("Sign as ${me?.name ?: "…"}", sign && canSign, enabled = canSign) { sign = it }
            CheckRow("Encrypt for me", toSelf && canSelf, enabled = canSelf) { toSelf = it }

            HorizontalDivider(Modifier.padding(top = 8.dp))
            SectionLabel("Encrypt for others")
            recipients.forEach { fpr ->
                val cert = certs.firstOrNull { it.fingerprint == fpr } ?: return@forEach
                ListItem(
                    headlineContent = { Text(cert.name, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                    supportingContent = { Text(cert.email ?: PgpUtil.formatFingerprint(cert.keyIdHex)) },
                    leadingContent = { Avatar(cert.name, cert.isSecret) },
                    trailingContent = {
                        IconButton(onClick = { recipients = recipients - fpr }) {
                            Icon(Icons.Filled.Close, contentDescription = "Remove")
                        }
                    },
                )
            }
            OutlinedButton(onClick = { picking = true }) {
                Icon(Icons.Filled.PersonAdd, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Add recipients")
            }

            Spacer(Modifier.size(8.dp))
            CheckRow("Encrypt with a password", usePassword) { usePassword = it }
            if (usePassword) {
                PasswordField(password, { password = it }, "Password")
                PasswordField(
                    password2, { password2 = it }, "Repeat password",
                    isError = password2.isNotEmpty() && password != password2,
                    supportingText = if (password2.isNotEmpty() && password != password2) "Passwords don't match" else null,
                    imeAction = ImeAction.Done,
                )
            }

            if (forFiles) {
                HorizontalDivider(Modifier.padding(vertical = 8.dp))
                CheckRow("Text output (ASCII armor, .asc)", armor) { armor = it }
            }

            if (request.sign && !request.encrypts) {
                Text(
                    if (forFiles) "Signing only: anyone can read the content, but they can check it came from you."
                    else "Signing only: the text stays readable and gets a signature block.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }

            Spacer(Modifier.size(16.dp))
            Button(
                onClick = { onConfirm(request) },
                enabled = valid,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(
                    when {
                        request.encrypts && request.sign -> "Sign & Encrypt"
                        request.encrypts -> "Encrypt"
                        request.sign -> "Sign"
                        else -> "Choose what to do"
                    },
                )
            }
        }
    }

    if (picking) {
        RecipientPicker(
            candidates = certs.filter { it.canEncrypt && it.fingerprint != myFpr },
            selected = recipients,
            onDismiss = { picking = false },
            onDone = { recipients = it; picking = false },
        )
    }
}

@Composable
fun EmptyState(icon: ImageVector, title: String, text: String, modifier: Modifier = Modifier, actions: @Composable () -> Unit = {}) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp),
        modifier = modifier.padding(32.dp),
    ) {
        Icon(icon, contentDescription = null, modifier = Modifier.size(56.dp), tint = MaterialTheme.colorScheme.primary)
        Text(title, style = MaterialTheme.typography.titleLarge)
        Text(text, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        actions()
    }
}
