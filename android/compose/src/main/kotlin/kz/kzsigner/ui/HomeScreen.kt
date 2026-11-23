package kz.kzsigner.ui

import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch
import kz.kzsigner.core.Unlock
import kz.kzsigner.KeysModel
import kz.kzsigner.Opened
import kz.kzsigner.R
import kz.kzsigner.hasFingerprint

/** Screen 1: Sign a document, Check a signature, the key chip (to Your keys), and Share. */
@Composable
fun HomeScreen(model: KeysModel, onKeys: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val tooBig = stringResource(R.string.too_big)
    val unreadable = stringResource(R.string.cant_read_file)
    val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            scope.launch {
                // the app goes where the file belongs (App.kt): Sign, or Add key for a key file
                when (model.open(uri)) {
                    Opened.DOCUMENT, Opened.KEY -> {}
                    Opened.TOO_BIG -> Toast.makeText(context, tooBig, Toast.LENGTH_LONG).show()
                    Opened.UNREADABLE -> Toast.makeText(context, unreadable, Toast.LENGTH_LONG).show()
                }
            }
        }
    }
    val pickToCheck = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) {
            scope.launch {
                when (model.openForCheck(uri)) {
                    Opened.TOO_BIG -> Toast.makeText(context, tooBig, Toast.LENGTH_LONG).show()
                    Opened.UNREADABLE -> Toast.makeText(context, unreadable, Toast.LENGTH_LONG).show()
                    // the app goes to Check (App.kt)
                    else -> {}
                }
            }
        }
    }
    val keys = model.keys?.keys.orEmpty()
    val confirm = if (keys.isEmpty()) R.string.home_sign_first else when (keys.firstOrNull()?.unlock) {
        Unlock.PASSWORD -> R.string.home_sign_password
        Unlock.FINGERPRINT, Unlock.FINGERPRINT_AND_PASSWORD -> R.string.home_sign_fingerprint
        else -> if (hasFingerprint(context)) R.string.home_sign_fingerprint else R.string.home_sign_lock
    }

    Screen(onBack = null) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            // never broken in two (large text): the name in the chip gives way instead
            Text("kzsigner", fontSize = 20.sp, fontWeight = FontWeight.Bold, softWrap = false)
            Spacer(Modifier.width(12.dp).weight(1f))
            Box(Modifier.weight(1f, fill = false)) { KeyChip(keys.firstOrNull()?.name, keys.isEmpty() && model.keys?.hidden != true, onKeys) }
        }
        Spacer(Modifier.size(8.dp))
        Surface(
            onClick = { pick.launch(arrayOf("*/*")) },
            shape = RoundedCornerShape(20.dp),
            color = MaterialTheme.colorScheme.primary,
            contentColor = MaterialTheme.colorScheme.onPrimary,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(Modifier.padding(22.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Icon(painterResource(R.drawable.ic_pen), null, modifier = Modifier.size(30.dp))
                Spacer(Modifier.size(4.dp))
                Text(stringResource(R.string.home_sign), fontSize = 24.sp, fontWeight = FontWeight.SemiBold)
                Text(stringResource(confirm), style = MaterialTheme.typography.bodyLarge)
            }
        }
        Surface(
            onClick = { pickToCheck.launch(arrayOf("*/*")) },
            shape = RoundedCornerShape(20.dp),
            color = MaterialTheme.colorScheme.surfaceVariant,
            border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Row(Modifier.padding(20.dp), horizontalArrangement = Arrangement.spacedBy(16.dp), verticalAlignment = Alignment.CenterVertically) {
                Icon(painterResource(R.drawable.ic_shield_check), null, tint = LocalNotices.current.good, modifier = Modifier.size(28.dp))
                Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(stringResource(R.string.home_check), fontSize = 18.sp, fontWeight = FontWeight.SemiBold)
                    Small(stringResource(R.string.home_check_body))
                }
            }
        }
        Spacer(Modifier.size(60.dp))
        Surface(shape = RoundedCornerShape(14.dp), color = MaterialTheme.colorScheme.surfaceVariant, modifier = Modifier.fillMaxWidth()) {
            Text(
                stringResource(R.string.home_share_hint),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(16.dp),
            )
        }
    }
}

/** The owner's first name in a pill: opens Your keys (Add key when there is none). */
@Composable
private fun KeyChip(name: String?, none: Boolean, onClick: () -> Unit) {
    // no key yet: the chip adds one
    val label = stringResource(if (none) R.string.add_key_short else R.string.your_keys)
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(50),
        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline),
        color = MaterialTheme.colorScheme.background,
        modifier = Modifier.heightIn(min = 48.dp).semantics { contentDescription = label },
    ) {
        Row(
            Modifier.padding(horizontal = 14.dp, vertical = 10.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(painterResource(R.drawable.ic_key), null, modifier = Modifier.size(18.dp))
            Text(name?.let { firstName(it) } ?: label, fontWeight = FontWeight.Medium, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
    }
}

/** "ИВАНОВ АЛИБЕК" (NCA writes the surname first) → "Алибек". */
fun firstName(name: String): String {
    val w = displayName(name).split(' ').filter { it.isNotEmpty() }
    return w.getOrNull(1) ?: w.firstOrNull() ?: name
}
