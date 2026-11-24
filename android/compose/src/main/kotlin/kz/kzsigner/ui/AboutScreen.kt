package kz.kzsigner.ui

import android.content.Intent
import android.net.Uri
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kz.kzsigner.R
import kz.kzsigner.core.version

const val SOURCE = "https://github.com/XakepSDK/easysigner-rs"

/** Screen 7c: what the app sends where, its version and license. */
@Composable
fun AboutScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    Screen(onBack) {
        Title(stringResource(R.string.about_title))
        Column(
            Modifier.fillMaxWidth().background(LocalNotices.current.infoBg, RoundedCornerShape(14.dp)).padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                stringResource(R.string.about_private_title),
                fontWeight = FontWeight.SemiBold,
                style = MaterialTheme.typography.titleMedium
            )
            Body(stringResource(R.string.about_private_body), MaterialTheme.colorScheme.onSurface)
        }
        Card {
            Row(stringResource(R.string.version), version())
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            Row(stringResource(R.string.talks_to), stringResource(R.string.talks_to_value))
            HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            Column(
                Modifier.fillMaxWidth().clickable(role = Role.Button) {
                    context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(SOURCE)))
                }
            ) {
                Row(stringResource(R.string.license), stringResource(R.string.license_value), link = true)
            }
        }
    }
}

@Composable
private fun Row(label: String, value: String, link: Boolean = false) {
    Column(Modifier.padding(vertical = 6.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Small(label)
        Text(value, color = if (link) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface)
    }
}
