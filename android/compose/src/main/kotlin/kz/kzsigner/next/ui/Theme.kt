package kz.kzsigner.next.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color

/** The design's colours that Material has no slot for: notices and their text. */
@Immutable
data class Notices(
    val warnBg: Color,
    val warnTitle: Color,
    val warnText: Color,
    val infoBg: Color,
    val good: Color,
    val badBg: Color,
)

private val LightNotices = Notices(
    warnBg = Color(0xFFFFF4DB),
    warnTitle = Color(0xFF5A3D05),
    warnText = Color(0xFF6B4500),
    infoBg = Color(0xFFEEF3FC),
    good = Color(0xFF1E7F4F),
    badBg = Color(0xFFFCEBEA),
)

private val DarkNotices = Notices(
    warnBg = Color(0xFF3A2E12),
    warnTitle = Color(0xFFFFE2A6),
    warnText = Color(0xFFF2D28F),
    infoBg = Color(0xFF1C2638),
    good = Color(0xFF6FD39F),
    badBg = Color(0xFF3B1C1A),
)

val LocalNotices = staticCompositionLocalOf { LightNotices }

private val Light = lightColorScheme(
    primary = Color(0xFF1F5EDB),
    onPrimary = Color.White,
    background = Color.White,
    onBackground = Color(0xFF14181F),
    surface = Color.White,
    onSurface = Color(0xFF14181F),
    surfaceVariant = Color(0xFFF3F5F9),
    onSurfaceVariant = Color(0xFF4A5363),
    outline = Color(0xFFD5DAE3),
    outlineVariant = Color(0xFFE4E8EF),
    error = Color(0xFFB42318),
    onError = Color.White,
)

private val Dark = darkColorScheme(
    primary = Color(0xFF8AB0FF),
    onPrimary = Color(0xFF0B1F4D),
    background = Color(0xFF111418),
    onBackground = Color(0xFFE6E9EF),
    surface = Color(0xFF111418),
    onSurface = Color(0xFFE6E9EF),
    surfaceVariant = Color(0xFF1D2229),
    onSurfaceVariant = Color(0xFFAEB6C4),
    outline = Color(0xFF3A414C),
    outlineVariant = Color(0xFF2A3038),
    error = Color(0xFFFF8A80),
    onError = Color(0xFF3B0A06),
)

@Composable
fun KzsignerTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    androidx.compose.runtime.CompositionLocalProvider(LocalNotices provides if (dark) DarkNotices else LightNotices) {
        MaterialTheme(colorScheme = if (dark) Dark else Light, content = content)
    }
}
