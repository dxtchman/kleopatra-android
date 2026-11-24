package io.github.dxtchman.kleo.ui

import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.isImeVisible
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.EditNote
import androidx.compose.material.icons.filled.Folder
import androidx.compose.material.icons.filled.Key
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import io.github.dxtchman.kleo.ui.certs.CertificateDetailScreen
import io.github.dxtchman.kleo.ui.certs.CertificatesScreen
import io.github.dxtchman.kleo.ui.certs.LookupScreen
import io.github.dxtchman.kleo.ui.certs.NewKeyScreen
import io.github.dxtchman.kleo.ui.common.BusyDialog
import io.github.dxtchman.kleo.ui.common.PassphraseDialog
import io.github.dxtchman.kleo.ui.files.FilesScreen
import io.github.dxtchman.kleo.ui.notepad.NotepadScreen

private data class Tab(val route: String, val label: String, val icon: ImageVector)

private val tabs = listOf(
    Tab(Routes.CERTS, "Certificates", Icons.Filled.Key),
    Tab(Routes.NOTEPAD, "Notepad", Icons.Filled.EditNote),
    Tab(Routes.FILES, "Files", Icons.Filled.Folder),
)

private fun NavHostController.switchTab(route: String) {
    navigate(route) {
        popUpTo(graph.findStartDestination().id) { saveState = true }
        launchSingleTop = true
        restoreState = true
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun KleoRoot(vm: AppViewModel) {
    val nav = rememberNavController()
    val snackbar = remember { SnackbarHostState() }
    val busy by vm.busy.collectAsStateWithLifecycle()
    val passphraseRequest by vm.passphraseRequest.collectAsStateWithLifecycle()

    LaunchedEffect(Unit) { vm.messages.collect { snackbar.showSnackbar(it) } }
    LaunchedEffect(Unit) {
        vm.navEvents.collect { route ->
            if (tabs.any { it.route == route }) nav.switchTab(route) else nav.navigate(route)
        }
    }

    val backStack by nav.currentBackStackEntryAsState()
    val current = backStack?.destination?.route
    val showBottomBar = tabs.any { it.route == current } && !WindowInsets.isImeVisible

    Scaffold(
        contentWindowInsets = WindowInsets(0),
        snackbarHost = { SnackbarHost(snackbar) },
        bottomBar = {
            if (showBottomBar) {
                NavigationBar {
                    tabs.forEach { tab ->
                        NavigationBarItem(
                            selected = current == tab.route,
                            onClick = { nav.switchTab(tab.route) },
                            icon = { Icon(tab.icon, contentDescription = null) },
                            label = { Text(tab.label) },
                        )
                    }
                }
            }
        },
    ) { padding ->
        NavHost(
            navController = nav,
            startDestination = Routes.CERTS,
            modifier = Modifier.padding(padding),
        ) {
            composable(Routes.CERTS) {
                CertificatesScreen(
                    vm = vm,
                    onOpen = { nav.navigate(Routes.cert(it)) },
                    onNewKey = { nav.navigate(Routes.NEW_KEY) },
                    onLookup = { nav.navigate(Routes.LOOKUP) },
                )
            }
            composable(Routes.NOTEPAD) { NotepadScreen(vm) }
            composable(Routes.FILES) { FilesScreen(vm) }
            composable(Routes.CERT) { entry ->
                val fpr = entry.arguments?.getString("fpr").orEmpty()
                CertificateDetailScreen(vm, fpr, onBack = { nav.popBackStack() })
            }
            composable(Routes.NEW_KEY) {
                NewKeyScreen(
                    vm = vm,
                    onBack = { nav.popBackStack() },
                    onCreated = { fpr ->
                        nav.popBackStack()
                        nav.navigate(Routes.cert(fpr))
                    },
                )
            }
            composable(Routes.LOOKUP) {
                LookupScreen(vm, onBack = { nav.popBackStack() }, onOpen = { nav.navigate(Routes.cert(it)) })
            }
        }
    }

    passphraseRequest?.let { request ->
        PassphraseDialog(request, check = vm::checkPassphrase)
    }
    if (busy != null && passphraseRequest == null) {
        BusyDialog(busy!!)
    }
}
