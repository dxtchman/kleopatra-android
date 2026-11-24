package io.github.dxtchman.kleo.ui.theme

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext

private val LightColors = lightColorScheme(
    primary = Color(0xFF1D4E89),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFD5E3FF),
    onPrimaryContainer = Color(0xFF001B3C),
    secondary = Color(0xFF555F71),
    tertiary = Color(0xFF6E5676),
)

private val DarkColors = darkColorScheme(
    primary = Color(0xFFA7C8FF),
    onPrimary = Color(0xFF003061),
    primaryContainer = Color(0xFF0F4789),
    onPrimaryContainer = Color(0xFFD5E3FF),
    secondary = Color(0xFFBDC7DC),
    tertiary = Color(0xFFDABDE2),
)

/** Status colours for operation results (Kleopatra's green / yellow / red banners). */
@Immutable
data class StatusColors(
    val okContainer: Color,
    val onOk: Color,
    val warnContainer: Color,
    val onWarn: Color,
    val errorContainer: Color,
    val onError: Color,
    val infoContainer: Color,
    val onInfo: Color,
)

private val LightStatus = StatusColors(
    okContainer = Color(0xFFDDF4DF), onOk = Color(0xFF0B5323),
    warnContainer = Color(0xFFFFF0C7), onWarn = Color(0xFF5C4300),
    errorContainer = Color(0xFFFFDAD6), onError = Color(0xFF8C1D18),
    infoContainer = Color(0xFFE3E8F2), onInfo = Color(0xFF243447),
)

private val DarkStatus = StatusColors(
    okContainer = Color(0xFF173B22), onOk = Color(0xFFB6EDC0),
    warnContainer = Color(0xFF453500), onWarn = Color(0xFFFFE08A),
    errorContainer = Color(0xFF5C1512), onError = Color(0xFFFFDAD6),
    infoContainer = Color(0xFF2A3340), onInfo = Color(0xFFD6E0EE),
)

val LocalStatusColors = staticCompositionLocalOf { LightStatus }

@Composable
fun KleoTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    val context = LocalContext.current
    val colors = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S ->
            if (dark) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        dark -> DarkColors
        else -> LightColors
    }
    androidx.compose.runtime.CompositionLocalProvider(
        LocalStatusColors provides if (dark) DarkStatus else LightStatus,
    ) {
        MaterialTheme(colorScheme = colors, content = content)
    }
}
