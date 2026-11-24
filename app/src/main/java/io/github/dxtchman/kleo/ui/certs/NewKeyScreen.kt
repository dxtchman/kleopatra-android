package io.github.dxtchman.kleo.ui.certs

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import io.github.dxtchman.kleo.crypto.KeyAlgorithm
import io.github.dxtchman.kleo.ui.AppViewModel
import io.github.dxtchman.kleo.ui.common.PasswordField
import io.github.dxtchman.kleo.ui.common.SectionLabel

private val EMAIL = Regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$")

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NewKeyScreen(vm: AppViewModel, onBack: () -> Unit, onCreated: (String) -> Unit) {
    var name by rememberSaveable { mutableStateOf("") }
    var email by rememberSaveable { mutableStateOf("") }
    var algorithm by rememberSaveable { mutableStateOf(KeyAlgorithm.CURVE25519) }
    var years by rememberSaveable { mutableIntStateOf(2) }
    var passphrase by rememberSaveable { mutableStateOf("") }
    var repeat by rememberSaveable { mutableStateOf("") }

    val emailError = email.isNotBlank() && !EMAIL.matches(email.trim())
    val mismatch = repeat.isNotEmpty() && passphrase != repeat
    val weak = passphrase.isNotEmpty() && passphrase.length < 8
    val valid = (name.isNotBlank() || email.isNotBlank()) && !emailError &&
        passphrase.isNotEmpty() && passphrase == repeat

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("New key pair") },
                navigationIcon = {
                    IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .padding(padding)
                .fillMaxSize()
                .imePadding()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 8.dp),
        ) {
            Text(
                "Your key pair lets others send you encrypted messages and lets you sign what you send. " +
                    "Enter your name and e-mail address so people can find and recognise your certificate.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.size(12.dp))
            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                label = { Text("Name") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Words, imeAction = ImeAction.Next),
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = email,
                onValueChange = { email = it },
                label = { Text("E-mail address") },
                singleLine = true,
                isError = emailError,
                supportingText = if (emailError) ({ Text("That doesn't look like an e-mail address") }) else null,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email, imeAction = ImeAction.Next),
                modifier = Modifier.fillMaxWidth(),
            )

            SectionLabel("Passphrase")
            PasswordField(
                passphrase, { passphrase = it }, "Passphrase",
                supportingText = if (weak) "Short passphrases are easy to guess. Consider a few random words." else null,
            )
            PasswordField(
                repeat, { repeat = it }, "Repeat passphrase",
                isError = mismatch,
                supportingText = if (mismatch) "Passphrases don't match" else null,
                imeAction = ImeAction.Done,
            )

            SectionLabel("Algorithm")
            Row {
                KeyAlgorithm.entries.forEach { alg ->
                    FilterChip(
                        selected = algorithm == alg,
                        onClick = { algorithm = alg },
                        label = { Text(if (alg == KeyAlgorithm.CURVE25519) "Curve25519" else alg.label) },
                        modifier = Modifier.padding(end = 8.dp),
                    )
                }
            }
            Text(
                when (algorithm) {
                    KeyAlgorithm.CURVE25519 -> "Modern, fast and secure. Recommended unless you need compatibility with very old software."
                    else -> "Widely compatible. Generating RSA keys on a phone can take up to a minute."
                },
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            SectionLabel("Valid until")
            listOf(1 to "1 year", 2 to "2 years", 3 to "3 years", 0 to "Never expires").forEach { (y, label) ->
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier
                        .fillMaxWidth()
                        .selectable(selected = years == y, role = Role.RadioButton) { years = y }
                        .padding(vertical = 2.dp),
                ) {
                    RadioButton(selected = years == y, onClick = null)
                    Spacer(Modifier.width(8.dp))
                    Text(label)
                }
            }

            Spacer(Modifier.size(24.dp))
            Button(
                onClick = {
                    vm.generateKey(name.trim(), email.trim(), algorithm, yearsFromNow(years), passphrase, onCreated)
                },
                enabled = valid,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Create key pair") }
            Spacer(Modifier.size(24.dp))
        }
    }
}
